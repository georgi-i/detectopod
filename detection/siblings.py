#!/usr/bin/env python3
"""READ-ONLY experiment: find "sibling" hostnames of domains already in the feed.

Phishing kits often use one throw-away registrable domain with several brand
sub-domains (econt.order401-20.shop, olx.order401-20.shop ...). The detector only
searches urlscan.io for brand keywords, so siblings without a monitored brand never
show up. This script asks urlscan for every hostname seen under the same registrable
domain and prints what the feed would gain. It NEVER writes to the feed.

    python detection/siblings.py --limit 15 --domains order401-20.shop
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

import requests

from detectopod import FREE_HOSTING_SUFFIXES, SUSPICIOUS_TLDS, contains_courier_keyword
from feedlib import FalsePositives, is_dev_host, load_json_list, normalize_domain

# Providers that hand out sub-domains to unrelated tenants: siblings mean nothing there.
SHARED_SUBDOMAIN_PROVIDERS = frozenset({'eu.cc', 'co.cc'})
# More hostnames than this under one registrable domain => probably a shared provider.
MAX_SIBLINGS = 50
SEARCH_URL = 'https://urlscan.io/api/v1/search/'


def registrable_domain(domain):
    """Last two labels when the domain is on its own (risky) TLD, else None."""
    d = normalize_domain(domain)
    labels = d.split('.')
    if len(labels) < 2 or d.endswith(FREE_HOSTING_SUFFIXES):
        return None
    reg = '.'.join(labels[-2:])
    if reg in SHARED_SUBDOMAIN_PROVIDERS or not reg.endswith(SUSPICIOUS_TLDS):
        return None
    return reg


def search_apex(session, apex, api_key):
    """Hostnames urlscan has seen on `apex`: {hostname: {'time', 'url'}}."""
    resp = session.get(SEARCH_URL, headers={'API-Key': api_key},
                       params={'q': f'page.apexDomain:{apex}', 'size': 100}, timeout=45)
    if resp.status_code != 200:
        raise RuntimeError(f'urlscan returned {resp.status_code}: {resp.text[:200]}')
    hosts = {}
    for r in resp.json().get('results', []):
        page = r.get('page', {})
        host = normalize_domain(page.get('domain') or urlparse(page.get('url', '')).netloc)
        if host and (host == apex or host.endswith('.' + apex)):
            hosts.setdefault(host, {'time': r.get('task', {}).get('time', ''), 'url': page.get('url', '')})
    return hosts


def pick_targets(feed, explicit, limit):
    """Explicit domains first, then the most recently detected feed entries."""
    targets = [normalize_domain(d) for d in explicit]
    for e in sorted(feed, key=lambda e: e.get('detected_at', ''), reverse=True):
        reg = registrable_domain(e['domain'])
        if reg and reg not in targets:
            targets.append(reg)
    return targets[:max(limit, len(explicit))]


def analyse(targets, feed, false_positives, search):
    """`search(apex) -> {host: info}`. Returns one result dict per registrable domain."""
    known = {normalize_domain(e['domain']) for e in feed}
    results = []
    for apex in targets:
        hosts = search(apex)
        row = {'apex': apex, 'seen': len(hosts), 'too_many': len(hosts) > MAX_SIBLINGS, 'new': []}
        if not row['too_many']:
            for host, info in sorted(hosts.items()):
                if host in known or host in false_positives or is_dev_host(host):
                    continue
                row['new'].append({'host': host, 'brand_keyword': contains_courier_keyword(host)[0], **info})
        results.append(row)
    return results


def main():
    parser = argparse.ArgumentParser(description='Read-only sibling lookup')
    parser.add_argument('--feed-file', default='feed/phishing_feed.json')
    parser.add_argument('--limit', type=int, default=15, help='registrable domains to check')
    parser.add_argument('--domains', nargs='*', default=[], help='extra registrable domains to check first')
    parser.add_argument('--report', default='siblings_report.json')
    args = parser.parse_args()

    api_key = os.environ.get('URLSCAN_API_KEY')
    if not api_key:
        sys.exit('URLSCAN_API_KEY is not set')

    feed = load_json_list(args.feed_file)
    fps = FalsePositives.load(os.path.join(os.path.dirname(args.feed_file), 'false_positives.json'))
    targets = pick_targets(feed, args.domains, args.limit)
    print(f'Checking {len(targets)} registrable domain(s); the feed is NOT modified.\n')

    session, failures = requests.Session(), 0

    def search(apex):
        nonlocal failures
        time.sleep(2)  # be gentle with the urlscan search quota
        try:
            hosts = search_apex(session, apex, api_key)
            failures = 0
            return hosts
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f'  ! {apex}: {e}')
            if failures >= 3:
                sys.exit('Stopping after 3 failed lookups in a row (quota?).')
            return {}

    results = analyse(targets, feed, fps, search)

    for row in results:
        flag = '  (TOO MANY hostnames - shared provider? ignored)' if row['too_many'] else ''
        print(f"{row['apex']}: {row['seen']} hostname(s) seen, {len(row['new'])} new{flag}")
        for n in row['new']:
            tag = 'brand keyword' if n['brand_keyword'] else 'NO brand keyword (invisible to the detector)'
            print(f"    + {n['host']}   [{tag}]   {n['time'][:10]}  {n['url'][:90]}")

    new = [n for r in results for n in r['new']]
    hidden = [n for n in new if not n['brand_keyword']]
    print(f"\nSummary: {len(results)} domain(s) checked, {sum(1 for r in results if r['new'])} with new siblings, "
          f"{len(new)} new hostname(s), {len(hidden)} of them invisible to the current detector.")
    with open(args.report, 'w') as f:
        json.dump(results, f, indent=2)


if __name__ == '__main__':
    main()
