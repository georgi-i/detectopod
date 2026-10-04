"""Shared helpers for the feed files (phishing_feed.json / false_positives.json).

false_positives.json is the single source of truth for "never show me this
again". Both the detector and the LLM analyzer consult it, so a domain that is
listed there is never re-added to the feed.

An entry is a dict with a ``domain`` key. Matching rules:
  * default           -> exact match (after normalisation, see normalize_domain)
  * "subdomains": true -> the domain AND every subdomain of it
                          (tollpass.xyz also covers test.tollpass.xyz,
                          dev.tollpass.xyz, www.ucntbtest.tollpass.xyz ...)
"""

import datetime
import json
import os

FEED_FILE = 'feed/phishing_feed.json'
FALSE_POSITIVES_FILE = 'feed/false_positives.json'


def normalize_domain(domain):
    """Lower-case, strip whitespace / trailing dot and a leading 'www.'."""
    d = (domain or '').strip().lower().rstrip('.')
    if d.startswith('www.'):
        d = d[4:]
    return d


# Leading labels that mark a dev/test/staging environment. A host like
# test.tollpass.xyz or dev.tollpass.xyz is a developer sandbox, not a phishing page.
DEV_LABELS = frozenset({'test', 'dev', 'staging', 'stage', 'qa', 'uat', 'sandbox'})


def is_dev_host(domain):
    """True for hosts whose first label is a dev/test/staging marker."""
    parts = normalize_domain(domain).split('.')
    return len(parts) > 2 and parts[0] in DEV_LABELS


def load_json_list(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def save_json_list(path, data):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


class FalsePositives:
    """Fast lookup over false_positives.json."""

    def __init__(self, entries):
        self.exact = set()
        self.subtrees = set()
        for entry in entries:
            d = normalize_domain(entry.get('domain'))
            if not d:
                continue
            self.exact.add(d)
            if entry.get('subdomains'):
                self.subtrees.add(d)

    @classmethod
    def load(cls, path=None):
        return cls(load_json_list(path or FALSE_POSITIVES_FILE))

    def __contains__(self, domain):
        d = normalize_domain(domain)
        if d in self.exact:
            return True
        # Walk up the parent domains: a.b.example.xyz -> b.example.xyz -> example.xyz
        labels = d.split('.')
        for i in range(1, len(labels) - 1):
            if '.'.join(labels[i:]) in self.subtrees:
                return True
        return False


def add_false_positive(domain, subdomains=False, reason='manual',
                       fp_path=FALSE_POSITIVES_FILE, feed_path=FEED_FILE):
    """Record a domain as false positive and drop it (and, if subdomains=True,
    everything below it) from the live feed. Returns the number of feed
    entries removed."""
    d = normalize_domain(domain)
    fps = load_json_list(fp_path)

    existing = next((e for e in fps if normalize_domain(e.get('domain')) == d), None)
    if existing is None:
        fps.append({
            'domain': d,
            'subdomains': bool(subdomains),
            'reason': reason,
            'added_at': datetime.datetime.utcnow().isoformat(),
        })
    elif subdomains and not existing.get('subdomains'):
        existing['subdomains'] = True
    save_json_list(fp_path, fps)

    matcher = FalsePositives([{'domain': d, 'subdomains': subdomains}])
    feed = load_json_list(feed_path)
    kept = [e for e in feed if e.get('domain') not in matcher]
    if len(kept) != len(feed):
        save_json_list(feed_path, kept)
    return len(feed) - len(kept)
