"""Deterministic triage for domains whose verdict is already certain.

The LLM prompt (llm_analyzer.py) lists a few "confirmed phishing" domain
structures that are always BLOCK. Asking the model about them wastes quota on
the free Gemini tier, so they are decided here without an API call. Anything
that does not match goes to the LLM as before.

The rules are deliberately narrow: a rule only fires when the structure is
unambiguous. Apex `tollpass.<tld>` domains, `speedy-<word>` and random strings
that merely contain `mvrbg` (e.g. fxktmvrbgsblq.top) are NOT matched.
"""

import re

from feedlib import is_dev_host, normalize_domain

# (rule name, regex on the normalised domain). Labels are separated by dots.
_RULES = [
    # speedy.bg-<anything>.<tld>            speedy.bg-iw.qpon
    ('speedy.bg-*',
     re.compile(r'(^|\.)speedy\.bg-[a-z0-9-]+\.[a-z0-9]+$')),
    # econt.bg-<anything>.<tld>             econt.bg-g63829.cfd
    ('econt.bg-*',
     re.compile(r'(^|\.)econt\.bg-[a-z0-9-]+\.[a-z0-9]+$')),
    # <brand>-bg as a label                 econt-bg.an537294.sbs
    ('brand-bg label',
     re.compile(r'(^|\.)(econt|speedy|bgpost)-bg([.\-]|$)')),
    # bgpost-<anything>.<tld>               bgpost-bga.life
    ('bgpost-*',
     re.compile(r'(^|\.)bgpost-[a-z0-9-]+\.[a-z0-9]+$')),
    # mvrbg / mvr-bg as a whole label       mvrbg.cam, gav.mvrbg.cam, mvr-bg.cfd
    ('mvrbg label',
     re.compile(r'(^|\.)(mvrbg|mvr-bg)(\.[a-z0-9-]+)*\.[a-z0-9]+$')),
    # mvr-gov-<anything>                    mvr-gov-mk.shop
    ('mvr-gov-*',
     re.compile(r'(^|\.)mvr-gov[a-z0-9-]*\.')),
    # e-uslugi<anything>.<tld>              e-uslugicye.top  (legit: e-uslugi.mvr.bg)
    ('e-uslugi*',
     re.compile(r'(^|\.)e-?uslugi[a-z0-9-]*\.(?!mvr\.bg$)[a-z0-9.-]+$')),
    # econt.<random>.<tld>, bgpost.<random>.<tld>   econt.png4kx.icu
    # (brand as a subdomain of a throw-away domain, same trick as tollpass.<random>)
    ('econt/bgpost.<random>.<tld>',
     re.compile(r'^(econt|bgpost)\.[a-z0-9-]+\.[a-z0-9]+$')),
    # tollpass.<random>.<tld>               tollpass.klgf.cam
    ('tollpass.<random>.<tld>',
     re.compile(r'^tollpass\.[a-z0-9-]+\.[a-z0-9]+$')),
    # tollpass<suffix>.<tld>                tollpassapp.top, tollpassss.cc
    ('tollpass<suffix>',
     re.compile(r'(^|\.)tollpass[a-z0-9-]+\.[a-z0-9]+$')),
]


def rule_based_decision(domain):
    """Return the rule name when `domain` is certain phishing, else None."""
    d = normalize_domain(domain)
    if not d or d.endswith('.mvr.bg') or d.endswith('.tollpass.bg') or d == 'tollpass.bg':
        return None  # the legitimate sites
    if is_dev_host(d):
        return None  # sandboxes are handled elsewhere; never auto-block them
    for name, pattern in _RULES:
        if pattern.search(d):
            return name
    return None
