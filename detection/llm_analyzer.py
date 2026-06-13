#!/usr/bin/env python3
"""
LLM-based phishing domain analyzer
Analyzes domains from feed using Google Gemini API directly
"""

import json
import os
import sys
import time
import argparse
import requests
from datetime import datetime, timedelta

# Google Gemini models — called directly via Google AI Studio REST API.
# No OpenRouter account needed; only your GEMINI_API_KEY is required.
#
# gemini-3.5-flash      → near-Pro reasoning, fast              ← default
# gemini-2.5-flash-lite → ultra-low latency, cheapest              ← budget option
MODEL = "gemini-3.5-flash"
# MODEL = "gemini-2.5-flash-lite"

# Google's OpenAI-compatible endpoint — same request/response format,
# no client library needed.
GOOGLE_API_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"


class GeminiAnalyzer:
    def __init__(self, api_key, model=MODEL):
        self.api_key = api_key
        self.model = model
        self.base_url = GOOGLE_API_BASE
        self.requests_made = 0
        # Limit is Google AI Studio quota, not a service cap.
        # 1000 is a safe default; raise freely for paid accounts.
        self.max_requests = 1000

    def analyze_domain(self, domain, score, keywords_found, cert_info):
        """Analyze a domain using the Gemini API."""
        if self.requests_made >= self.max_requests:
            print(f"⚠️  Request limit reached ({self.max_requests}). Raise max_requests if needed.")
            return None

        prompt = f"""Analyze this potential phishing domain flagged by a rule-based system targeting Bulgarian online services.

Domain: {domain}
Rule-based Score: {score}/100
Keywords: {', '.join(keywords_found) if keywords_found else 'None'}
Hosting: Free/serverless platform or suspicious TLD
Targets monitored:
  - Bulgarian courier services: Econt, Speedy, BulgariaPost
  - Bulgarian Ministry of Interior (MVR) e-services portal: e-uslugi.mvr.bg

=== CONFIRMED PHISHING PATTERNS — ALWAYS BLOCK ===
These domain structures are unambiguous phishing. If the domain matches, BLOCK immediately
without considering false positive scenarios:

1. speedy.bg-<anything>.<tld>  e.g. speedy.bg-iw.qpon, speedy.bg-po.qpon, speedy.bg-pk.cfd
   → Impersonates speedy.bg (Bulgaria's Speedy courier) via subdomain abuse. No legitimate
     business structures a domain this way.

2. mvrbg.<tld> or mvr-bg.<tld>  e.g. mvrbg.cam, mvr-bg.cfd, mvrbg.life
   → "mvrbg" is a concatenation of the Bulgarian Ministry of Interior acronym (MVR) and
     country code (BG). No legitimate entity outside Bulgaria's government uses this string.

3. <brand>.<geo>-<anything>.<tld>  e.g. econt.bg-g63829.cfd, speedy.bg-packv.cfd
   → Brand + Bulgarian geo indicator + suspicious TLD = courier phishing.

4. bgpost-<anything>.<tld>  e.g. bgpost-bga.life
   → BulgariaPost brand on a suspicious TLD. BulgariaPost only operates from bgpost.bg.

5. gav.mvrbg.<tld>  e.g. gav.mvrbg.cam
   → "gav" (Bulgarian: "гав") + mvrbg = MVR government phishing subdomain.

6. e-uslugi<anything>.<tld>  e.g. e-uslugicye.top, e-uslugiaca.top
   → The legitimate portal is e-uslugi.mvr.bg only. Any other domain with this prefix is
     phishing.

=== FALSE POSITIVE CHECK — only apply when NO confirmed pattern above matches ===
Only consider a domain a false positive if it CLEARLY indicates an unrelated legitimate
business with no plausible courier or government impersonation angle:
- Unrelated businesses where "speedy" is a generic adjective: speedy-glass, speedy-loans,
  speedy-removals, speedy-medical, speedy-marketing, speedy-bookkeeper
- Personal/entertainment pages: birthdays, pets, gaming, celebrity net worth
- Developer/test pages: domains containing "test", "test-project", "qa", "backoffice"
- Productivity tools: calculators, assignment helpers
- Router/IoT hostnames

Provide structured analysis:
1. Threat Level: HIGH/MEDIUM/LOW
2. Confidence: 0-100%
3. Key Indicators: List 2-3 specific reasons for your decision
4. Decision: BLOCK/INVESTIGATE/FALSE_POSITIVE

Be concise and accurate. When in doubt between BLOCK and FALSE_POSITIVE, choose BLOCK."""

        try:
            response = requests.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Be concise."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 300,
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                self.requests_made += 1

                # 1s delay avoids burst rate-limit spikes on the direct API
                time.sleep(1)

                return {
                    'analysis': analysis,
                    'model': self.model,
                    'timestamp': datetime.utcnow().isoformat(),
                    'threat_level': self._extract_threat_level(analysis),
                    'decision': self._extract_decision(analysis)
                }
            else:
                print(f"❌ API error {response.status_code}: {response.text}")
                return None

        except Exception as e:
            print(f"❌ Error analyzing {domain}: {e}")
            return None

    def _extract_threat_level(self, analysis):
        """Extract threat level from analysis text"""
        analysis_upper = analysis.upper()
        if 'THREAT LEVEL: HIGH' in analysis_upper or 'HIGH' in analysis_upper.split('\n')[0]:
            return 'HIGH'
        elif 'THREAT LEVEL: MEDIUM' in analysis_upper or 'MEDIUM' in analysis_upper.split('\n')[0]:
            return 'MEDIUM'
        elif 'THREAT LEVEL: LOW' in analysis_upper or 'LOW' in analysis_upper.split('\n')[0]:
            return 'LOW'
        return 'UNKNOWN'

    def _extract_decision(self, analysis):
        """Extract decision from analysis text"""
        analysis_upper = analysis.upper()
        if 'BLOCK' in analysis_upper:
            return 'BLOCK'
        elif 'FALSE_POSITIVE' in analysis_upper or 'FALSE POSITIVE' in analysis_upper:
            return 'FALSE_POSITIVE'
        elif 'INVESTIGATE' in analysis_upper:
            return 'INVESTIGATE'
        return 'UNKNOWN'


def main():
    parser = argparse.ArgumentParser(description='LLM Analysis for Phishing Domains')
    parser.add_argument('--days', type=int, default=1, help='Analyze domains from last N days')
    parser.add_argument('--max-analyze', type=int, default=1000, help='Maximum domains to analyze')
    parser.add_argument('--min-score', type=int, default=75, help='Minimum score to analyze')
    parser.add_argument('--feed-file', default='feed/phishing_feed.json', help='Feed file path')
    parser.add_argument('--reanalyze', action='store_true',
                        help='Strip existing llm_analysis and re-evaluate all entries (backfill mode)')
    args = parser.parse_args()

    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        print("❌ Error: GEMINI_API_KEY environment variable not set")
        sys.exit(1)

    if not os.path.exists(args.feed_file):
        print(f"❌ Feed file not found: {args.feed_file}")
        sys.exit(1)

    with open(args.feed_file, 'r') as f:
        feed = json.load(f)

    if args.reanalyze:
        stripped = sum(1 for e in feed if 'llm_analysis' in e)
        for entry in feed:
            entry.pop('llm_analysis', None)
            entry.pop('flagged_false_positive', None)
        print(f"🔄 Reanalyze mode: stripped existing analysis from {stripped} entries")

    cutoff_date = datetime.now() - timedelta(days=args.days)
    to_analyze = []

    for entry in feed:
        if 'llm_analysis' in entry:
            continue

        if entry.get('score', 0) < args.min_score:
            continue

        entry_date_str = entry.get('discovered_date') or entry.get('first_seen')
        if entry_date_str:
            try:
                entry_date = datetime.fromisoformat(entry_date_str.replace('Z', '+00:00'))
                if entry_date < cutoff_date:
                    continue
            except:
                pass

        to_analyze.append(entry)

    to_analyze = sorted(to_analyze, key=lambda x: x.get('score', 0), reverse=True)[:args.max_analyze]

    if not to_analyze:
        print("✓ No domains need analysis")
        return

    print(f"\n🔍 Analyzing {len(to_analyze)} domains with LLM...")
    print(f"   Model: {MODEL} (Google AI Studio direct)")
    print(f"   Targets: Bulgarian couriers + MVR e-services")
    print(f"   Limit: up to 1000 requests (Google AI Studio quota)\n")

    analyzer = GeminiAnalyzer(api_key)

    stats = {
        'analyzed_count': 0,
        'high_confidence': 0,
        'medium_confidence': 0,
        'false_positives': 0,
        'errors': 0
    }

    for i, entry in enumerate(to_analyze, 1):
        domain = entry.get('domain', 'unknown')
        score = entry.get('score', 0)
        keywords = entry.get('keywords', [])

        print(f"[{i}/{len(to_analyze)}] Analyzing: {domain} (score: {score})")

        result = analyzer.analyze_domain(domain, score, keywords, entry)

        if result:
            entry['llm_analysis'] = result
            stats['analyzed_count'] += 1

            if result['threat_level'] == 'HIGH':
                stats['high_confidence'] += 1
                print(f"   ✓ HIGH threat confirmed")
            elif result['threat_level'] == 'MEDIUM':
                stats['medium_confidence'] += 1
                print(f"   ⚠️  MEDIUM threat")
            elif result['decision'] == 'FALSE_POSITIVE':
                stats['false_positives'] += 1
                entry['flagged_false_positive'] = True
                print(f"   ✅ Marked as false positive")
            else:
                print(f"   ℹ️  {result['threat_level']}")
        else:
            stats['errors'] += 1
            print(f"   ❌ Analysis failed")

    false_positive_domains = [
        entry for entry in feed
        if entry.get('llm_analysis', {}).get('decision') == 'FALSE_POSITIVE'
        or entry.get('flagged_false_positive')
    ]
    clean_feed = [
        entry for entry in feed
        if not (
            entry.get('llm_analysis', {}).get('decision') == 'FALSE_POSITIVE'
            or entry.get('flagged_false_positive')
        )
    ]

    with open(args.feed_file, 'w') as f:
        json.dump(clean_feed, f, indent=2)

    fp_file = os.path.join(os.path.dirname(args.feed_file), 'false_positives.json')
    existing_fps = []
    if os.path.exists(fp_file):
        with open(fp_file, 'r') as f:
            try:
                existing_fps = json.load(f)
            except json.JSONDecodeError:
                existing_fps = []
    existing_fp_domains = {e['domain'] for e in existing_fps}
    new_fps = [e for e in false_positive_domains if e['domain'] not in existing_fp_domains]
    existing_fps.extend(new_fps)
    with open(fp_file, 'w') as f:
        json.dump(existing_fps, f, indent=2)

    if false_positive_domains:
        print(f"\n🗑️  Removed {len(false_positive_domains)} false positive(s) from feed:")
        for fp in false_positive_domains:
            print(f"   - {fp['domain']}")
        print(f"   Saved to: {fp_file}")

    stats['false_positives'] = len(false_positive_domains)
    stats['timestamp'] = datetime.utcnow().isoformat()
    stats_file = os.path.join(os.path.dirname(args.feed_file), 'llm_analysis_stats.json')
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)

    print(f"\n{'='*60}")
    print(f"✓ Analysis Complete")
    print(f"{'='*60}")
    print(f"  Domains analyzed:          {stats['analyzed_count']}")
    print(f"  High confidence threats:   {stats['high_confidence']}")
    print(f"  Medium threats:            {stats['medium_confidence']}")
    print(f"  False positives removed:   {stats['false_positives']}")
    print(f"  Errors:                    {stats['errors']}")
    print(f"  Clean feed size:           {len(clean_feed)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
