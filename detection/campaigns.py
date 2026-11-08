#!/usr/bin/env python3
"""Temporary campaign: phishing around Eurovision 2027 (Burgas, May 2027).

READ-ONLY for now: collects candidate domains from urlscan.io and crt.sh, checks
whether they serve a Bulgarian (/bg) page, classifies them and prints a report.
It NEVER writes to feed/.

    python detection/campaigns.py --days 30 --probe

The campaign switches itself off after ACTIVE_UNTIL.
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

import requests

from feedlib import FalsePositives, load_json_list, normalize_domain

CAMPAIGN = 'eurovision-2027'
ACTIVE_UNTIL = datetime.date(2027, 5, 31)

# euro-vision, eurovision, evrovizia/evroviziya/eurovizija, common typos, 2027 context.
# (?<!n) keeps "neurovision" (eye clinics etc.) out.
NAME_RE = re.compile(r'(?<!n)(euro|evro)-?vi[sz]i(on|ya|a|ja|q)|eurovison|eurovisiion'
                     r'|burgas-?2027|esc-?2027')

# Legitimate sites (and all their sub-domains).
# The only official ticket sale is eurovision.com/tickets; eurovision2027.bg is BNT's site.
ALLOWLIST = ('eurovision.tv', 'eurovision.com', 'eurovision.de', 'eurovisionworld.com', 'wiwibloggs.com',
             'eurovoix.com', 'escxtra.com', 'bnt.bg', 'eurovision2027.bg')

URLSCAN_TERMS = ('eurovision', 'euro-vision', 'evrovizi', 'eurovizi', 'burgas2027', 'esc2027')
CRTSH_PATTERNS = ('%eurovision%', '%euro-vision%', '%evrovizi%', '%eurovizi%', '%burgas2027%')

BG_PATH_RE = re.compile(r'(^|/)(bg|bg-bg|bul)(/|$)', re.I)


def is_active(today=None):
    return (today or datetime.date.today()) <= ACTIVE_UNTIL


def matches_name(domain):
    return bool(NAME_RE.search(normalize_domain(domain)))


def is_allowlisted(domain):
    d = normalize_domain(domain)
    return any(d == a or d.endswith('.' + a) for a in ALLOWLIST)


def is_bg_url(url):
    """True when the URL points at a Bulgarian-language page (/bg/, /bg-bg/, ?lang=bg ...)."""
    p = urlparse(url or '')
    return bool(BG_PATH_RE.search(p.path)) or 'lang=bg' in p.query.lower()


def classify(domain, bg_url):
    if is_allowlisted(domain):
        return 'allowlisted'
    if not matches_name(domain):
        return 'no-name-match'
    return 'block (name + /bg)' if bg_url else 'llm review (name only)'


# ---------- sources ----------

def urlscan_candidates(session, api_key, days):
    """{domain: {'sources', 'urls', 'first_seen'}} from urlscan.io."""
    since = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    terms = ' OR '.join(f'page.domain:*{t}*' for t in URLSCAN_TERMS)
    resp = session.get('https://urlscan.io/api/v1/search/', headers={'API-Key': api_key},
                       params={'q': f'({terms}) AND date:>{since}', 'size': 1000}, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f'urlscan returned {resp.status_code}: {resp.text[:200]}')
    out = {}
    for r in resp.json().get('results', []):
        page = r.get('page', {})
        url = page.get('url', '')
        d = normalize_domain(page.get('domain') or urlparse(url).netloc)
        if not d:
            continue
        c = out.setdefault(d, {'sources': {'urlscan'}, 'urls': set(), 'first_seen': ''})
        c['urls'].add(url)
        t = r.get('task', {}).get('time', '')
        if t and (not c['first_seen'] or t < c['first_seen']):
            c['first_seen'] = t
    return out


def parse_crtsh(entries, days, today=None):
    """Domains from crt.sh JSON whose certificate was issued in the last `days` days."""
    cutoff = (today or datetime.date.today()) - datetime.timedelta(days=days)
    out = {}
    for e in entries:
        try:
            issued = datetime.date.fromisoformat(e.get('not_before', '')[:10])
        except ValueError:
            continue
        if issued < cutoff:
            continue
        for name in e.get('name_value', '').split('\n'):
            d = normalize_domain(name.lstrip('*.'))
            if d and '.' in d:
                c = out.setdefault(d, {'sources': {'crt.sh'}, 'urls': set(), 'first_seen': ''})
                if not c['first_seen'] or issued.isoformat() < c['first_seen']:
                    c['first_seen'] = issued.isoformat()
    return out


def crtsh_candidates(session, days):
    out = {}
    for pattern in CRTSH_PATTERNS:
        for attempt in range(3):  # crt.sh is often slow or overloaded
            try:
                resp = session.get('https://crt.sh/', params={'q': pattern, 'output': 'json', 'exclude': 'expired'},
                                   timeout=90)
                if resp.status_code == 200:
                    for d, c in parse_crtsh(resp.json(), days).items():
                        merge(out, d, c)
                    break
                print(f'  ! crt.sh {pattern}: HTTP {resp.status_code}')
            except Exception as e:  # noqa: BLE001
                print(f'  ! crt.sh {pattern}: {e}')
            time.sleep(5 * (attempt + 1))
    return out


def probe_bg(session, domain):
    """GET https://<domain>/bg/ (no JS, no forms). Returns the final URL when it is a /bg page."""
    for path in ('/bg/', '/bg'):
        try:
            r = session.get(f'https://{domain}{path}', timeout=10, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0 (detectopod campaign check)'})
            if r.status_code == 200 and is_bg_url(r.url):
                return r.url
        except Exception:  # noqa: BLE001
            return ''
    return ''


def merge(into, domain, cand):
    c = into.setdefault(domain, {'sources': set(), 'urls': set(), 'first_seen': ''})
    c['sources'] |= cand['sources']
    c['urls'] |= cand['urls']
    if cand['first_seen'] and (not c['first_seen'] or cand['first_seen'] < c['first_seen']):
        c['first_seen'] = cand['first_seen']


def build_report(candidates, feed, false_positives, prober=None, max_probes=40):
    known = {normalize_domain(e['domain']) for e in feed}
    rows, probes = [], 0
    for d in sorted(candidates):
        c = candidates[d]
        if d in false_positives:
            continue
        bg_url = next((u for u in sorted(c['urls']) if is_bg_url(u)), '')
        if not bg_url and prober and matches_name(d) and not is_allowlisted(d) and probes < max_probes:
            probes += 1
            bg_url = prober(d)
        rows.append({'domain': d, 'sources': sorted(c['sources']), 'first_seen': c['first_seen'][:10],
                     'bg_url': bg_url, 'in_feed': d in known, 'class': classify(d, bg_url)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=f'Read-only trial of the {CAMPAIGN} campaign')
    parser.add_argument('--feed-file', default='feed/phishing_feed.json')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--probe', action='store_true', help='GET /bg/ on name matches without a /bg URL')
    parser.add_argument('--report', default='campaign_report.json')
    args = parser.parse_args()

    if not is_active():
        print(f'Campaign {CAMPAIGN} ended on {ACTIVE_UNTIL}; nothing to do.')
        return
    api_key = os.environ.get('URLSCAN_API_KEY')
    if not api_key:
        sys.exit('URLSCAN_API_KEY is not set')

    feed = load_json_list(args.feed_file)
    fps = FalsePositives.load(os.path.join(os.path.dirname(args.feed_file), 'false_positives.json'))
    session = requests.Session()

    candidates = {}
    try:
        for d, c in urlscan_candidates(session, api_key, args.days).items():
            merge(candidates, d, c)
    except Exception as e:  # noqa: BLE001
        print(f'  ! urlscan: {e}')
    for d, c in crtsh_candidates(session, args.days).items():
        merge(candidates, d, c)

    rows = build_report(candidates, feed, fps, prober=(lambda d: probe_bg(session, d)) if args.probe else None)
    print(f'{CAMPAIGN}: {len(rows)} candidate domain(s) in the last {args.days} days. The feed is NOT modified.\n')
    order = ['block (name + /bg)', 'llm review (name only)', 'allowlisted', 'no-name-match']
    for cls in order:
        group = [r for r in rows if r['class'] == cls]
        print(f'== {cls}: {len(group)}')
        for r in group[:60]:
            feed_tag = '  [already in feed]' if r['in_feed'] else ''
            print(f"   {r['domain']:40} {','.join(r['sources']):15} {r['first_seen']:10} {r['bg_url'][:70]}{feed_tag}")
        if len(group) > 60:
            print(f'   ... {len(group) - 60} more in the report file')
    with open(args.report, 'w') as f:
        json.dump(rows, f, indent=2)


if __name__ == '__main__':
    main()
