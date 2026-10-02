#!/usr/bin/env python3
"""Mark domains as false positives.

Usage (from the repo root):
    python detection/fp.py tollpass.xyz --subdomains
    python detection/fp.py some-domain.top other.cfd --reason "legit shop"

The domain is added to feed/false_positives.json and removed from
feed/phishing_feed.json; the detector will not add it again.
"""

import argparse

from feedlib import add_false_positive


def main():
    parser = argparse.ArgumentParser(description='Mark domains as false positives')
    parser.add_argument('domains', nargs='+')
    parser.add_argument('--subdomains', action='store_true',
                        help='also suppress every subdomain (test.x, dev.x, www.x ...)')
    parser.add_argument('--reason', default='manual')
    args = parser.parse_args()

    for domain in args.domains:
        removed = add_false_positive(domain, subdomains=args.subdomains, reason=args.reason)
        print(f"✓ {domain}: marked as false positive"
              f"{' (+subdomains)' if args.subdomains else ''}, removed {removed} feed entr{'y' if removed == 1 else 'ies'}")


if __name__ == '__main__':
    main()
