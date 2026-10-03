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

from feedlib import FalsePositives, normalize_domain, load_json_list, save_json_list
from rules import rule_based_decision

# Google Gemini models — called directly via Google AI Studio REST API (free tier
# is enough: only GEMINI_API_KEY is required).
#
# gemini-2.5-flash-lite → cheapest, no thinking tokens, highest free quota   ← default
# gemini-3.5-flash      → stronger reasoning but a much smaller free quota   ← fallback
#
# Each model has its own quota, so a 429 on one is answered by trying the other
# straight away instead of sleeping.
MODEL          = "gemini-2.5-flash-lite"
MODEL_FALLBACK = "gemini-3.5-flash"

# Minimum seconds between two API requests (keeps us under the free-tier requests per
# minute instead of bursting and then backing off for minutes). Override with the
# LLM_MIN_INTERVAL environment variable.
MIN_REQUEST_INTERVAL = float(os.environ.get('LLM_MIN_INTERVAL', '6'))
# After every model returned 429, wait this long once before a second round.
RATE_LIMIT_COOLDOWN = 60

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
        self._last_request = float('-inf')  # first request never waits

    def analyze_domain(self, domain, score, keywords_found, cert_info):
        """Analyze a domain using the Gemini API."""
        if self.requests_made >= self.max_requests:
            print(f"⚠️  Request limit reached ({self.max_requests}). Raise max_requests if needed.")
            return None

        prompt = f"""Analyze this potential phishing domain flagged by a rule-based system targeting Bulgarian online services.

Domain: {domain}
Rule-based Score: {score}/100 (the score saturates at 100 for almost everything - do not treat it as evidence)
Keywords: {', '.join(keywords_found) if keywords_found else 'None'}
Hosting: Free/serverless platform or suspicious TLD
Targets monitored (legitimate sites in brackets):
  - Bulgarian courier services: Econt, Speedy, BulgariaPost  [econt.com, speedy.bg, bgpost.bg]
  - Bulgarian Ministry of Interior (MVR) e-services portal  [e-uslugi.mvr.bg]
  - Bulgarian toll/vignette services: TollPass, Vinetki  [tollpass.bg, vinetki.bg]

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

7. tollpass<random>.<tld> or tollpass.<random>.<tld>  e.g. tollpass.klgf.cam, tollpassapp.top,
   tollpassss.cc
   → TollPass only operates from tollpass.bg. A random/short suffix on a cheap TLD is phishing.

=== FALSE POSITIVE CHECK — only apply when NO confirmed pattern above matches ===
Answer FALSE_POSITIVE when the domain CLEARLY indicates an unrelated or non-malicious host
with no plausible courier, government or toll impersonation angle:
- Developer / test / staging environments: a leading label of test, dev, staging, qa, uat,
  sandbox, or a name containing "test" (test.tollpass.xyz, dev.tollpass.xyz, ucntbtest.x.xyz).
  A dev host is not a phishing page, even on a cheap TLD.
- Unrelated businesses where "speedy" is a generic adjective: speedy-glass, speedy-loans,
  speedy-removals, speedy-medical, speedy-marketing, speedy-bookkeeper
- Personal/entertainment pages: birthdays, pets, gaming, celebrity net worth
- Productivity tools: calculators, assignment helpers
- Router/IoT hostnames

Use INVESTIGATE only when the domain genuinely could be either and you cannot decide from the
name alone. Do NOT default to BLOCK just because the TLD is cheap or the score is high.

Respond with ONLY a JSON object, no prose and no markdown fences, using exactly these keys:
{{"threat_level": "HIGH" | "MEDIUM" | "LOW",
  "confidence": <integer 0-100>,
  "indicators": [<2-3 short strings>],
  "decision": "BLOCK" | "INVESTIGATE" | "FALSE_POSITIVE"}}"""

        models_to_try = [self.model]
        if MODEL_FALLBACK and MODEL_FALLBACK != self.model:
            models_to_try.append(MODEL_FALLBACK)

        for round_no in range(2):
            rate_limited = set()
            for model_id in models_to_try:
                result = self._try_model(model_id, prompt, rate_limited)
                if result:
                    return result
            if len(rate_limited) < len(models_to_try) or round_no == 1:
                break  # failed for a reason other than quota, or already waited once
            print(f"   ⏳ every model is rate limited, cooling down {RATE_LIMIT_COOLDOWN}s...")
            time.sleep(RATE_LIMIT_COOLDOWN)

        print(f"❌ All models/retries exhausted for {domain}")
        return None

    def _pace(self):
        """Sleep so that requests are at least MIN_REQUEST_INTERVAL apart."""
        wait = MIN_REQUEST_INTERVAL - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _try_model(self, model_id, prompt, rate_limited):
        """One model: up to 3 attempts for transient errors. On 429 give up on this
        model immediately (it has its own quota) and record it in `rate_limited`."""
        for attempt in range(3):
            try:
                self._pace()
                response = requests.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model_id,
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity expert. Be concise."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.2,
                        # Generous: gemini-3.5-flash is a thinking model and its
                        # reasoning tokens count against this budget. 300 used to
                        # truncate the answer mid-sentence (-> decision UNKNOWN).
                        "max_tokens": 4096,
                        "response_format": {"type": "json_object"},
                    },
                    timeout=90
                )

                if response.status_code == 200:
                    choice = response.json()['choices'][0]
                    analysis = choice['message'].get('content') or ''
                    self.requests_made += 1
                    parsed = self._parse_response(analysis)
                    if choice.get('finish_reason') == 'length' or parsed is None:
                        # Truncated / malformed: never store it. The entry stays
                        # un-analysed and is retried on the next run.
                        print(f"   ⚠️  {model_id} returned an unusable answer, retrying...")
                        continue
                    if model_id != self.model:
                        print(f"   ↳ used fallback model: {model_id}")
                    return {
                        'analysis': analysis,
                        'model': model_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'threat_level': parsed['threat_level'],
                        'confidence': parsed['confidence'],
                        'decision': parsed['decision'],
                    }

                if response.status_code == 503:
                    wait = 10 * (attempt + 1)  # 10s, 20s, 30s
                    print(f"   ⚠️  {model_id} overloaded (503), retrying in {wait}s... (attempt {attempt+1}/3)")
                    time.sleep(wait)
                    continue

                if response.status_code == 429:
                    print(f"   ⚠️  {model_id} rate limited (429): {response.text[:300]!r}")
                    rate_limited.add(model_id)
                    return None

                print(f"❌ API error {response.status_code}: {response.text[:300]}")
                return None  # non-retryable — try next model

            except requests.exceptions.Timeout:
                print(f"   ⚠️  {model_id} timed out (attempt {attempt+1}/3), retrying...")
                time.sleep(5)
            except Exception as e:
                print(f"❌ Error calling {model_id}: {e}")
                return None
        return None

    VALID_LEVELS = ('HIGH', 'MEDIUM', 'LOW')
    VALID_DECISIONS = ('BLOCK', 'INVESTIGATE', 'FALSE_POSITIVE')

    def _parse_response(self, text):
        """Parse the model's JSON answer. Returns a validated dict or None."""
        text = (text or '').strip()
        if text.startswith('```'):
            text = text.strip('`')
            if text.lower().startswith('json'):
                text = text[4:]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Last resort: the first {...} block in the text
            start, end = text.find('{'), text.rfind('}')
            if start == -1 or end <= start:
                return None
            try:
                data = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
        if not isinstance(data, dict):
            return None

        level = str(data.get('threat_level', '')).strip().upper()
        decision = str(data.get('decision', '')).strip().upper().replace(' ', '_')
        if level not in self.VALID_LEVELS or decision not in self.VALID_DECISIONS:
            return None
        try:
            confidence = int(data.get('confidence', 0))
        except (TypeError, ValueError):
            confidence = 0
        return {'threat_level': level, 'decision': decision, 'confidence': confidence}


SAVE_EVERY = 10  # persist progress after this many analysed domains
# Stop the run after this many failures in a row. A failure means every retry and the
# fallback model were exhausted (~6 min per domain when the API quota is used up), so
# continuing would only burn the CI time budget.
MAX_CONSECUTIVE_FAILURES = 3


def save_progress(feed, feed_file):
    """Write the feed (minus false positives) and false_positives.json.

    Called every SAVE_EVERY domains and once at the end, so a crash or a CI
    timeout in the middle of a long run keeps everything analysed so far.
    Returns the list of entries that are false positives.
    """
    def is_fp(entry):
        return (entry.get('llm_analysis', {}).get('decision') == 'FALSE_POSITIVE'
                or entry.get('flagged_false_positive'))

    false_positive_domains = [e for e in feed if is_fp(e)]
    clean_feed = [e for e in feed if not is_fp(e)]
    save_json_list(feed_file, clean_feed)

    fp_file = os.path.join(os.path.dirname(feed_file), 'false_positives.json')
    existing_fps = load_json_list(fp_file)
    existing_fp_domains = {normalize_domain(e['domain']) for e in existing_fps}
    existing_fps.extend(e for e in false_positive_domains
                        if normalize_domain(e['domain']) not in existing_fp_domains)
    save_json_list(fp_file, existing_fps)
    return false_positive_domains, clean_feed, fp_file


def write_stats(stats, feed_file):
    stats['timestamp'] = datetime.utcnow().isoformat()
    stats_file = os.path.join(os.path.dirname(feed_file), 'llm_analysis_stats.json')
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='LLM Analysis for Phishing Domains')
    parser.add_argument('--days', type=int, default=1, help='Analyze domains from last N days')
    parser.add_argument('--max-analyze', type=int, default=25,
                        help='Maximum domains sent to the LLM per run (rule-matched domains are free)')
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

    # Entries analysed earlier with a truncated answer (decision UNKNOWN) carry no
    # information - drop that analysis so they are picked up again below.
    unknown = 0
    for entry in feed:
        if entry.get('llm_analysis', {}).get('decision') == 'UNKNOWN':
            entry.pop('llm_analysis')
            unknown += 1
    if unknown:
        print(f"🔁 Re-queued {unknown} entries with an UNKNOWN (truncated) analysis")

    # Never analyse (or keep) anything that is already a known false positive
    false_positives = FalsePositives.load(os.path.join(os.path.dirname(args.feed_file), 'false_positives.json'))
    before = len(feed)
    feed = [e for e in feed if e.get('domain') not in false_positives]
    if len(feed) != before:
        print(f"🧹 Dropped {before - len(feed)} known false positive(s) from the feed")

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

        entry_date_str = entry.get('detected_at') or entry.get('discovered_date') or entry.get('first_seen')
        if entry_date_str:
            try:
                entry_date = datetime.fromisoformat(entry_date_str.replace('Z', '+00:00'))
                if entry_date < cutoff_date:
                    continue
            except:
                pass

        to_analyze.append(entry)

    to_analyze = sorted(to_analyze, key=lambda x: x.get('score', 0), reverse=True)

    # Certain phishing structures are decided by rules.py - no API call, no quota.
    rule_hits = 0
    llm_queue = []
    for entry in to_analyze:
        rule = rule_based_decision(entry.get('domain', ''))
        if rule:
            entry['llm_analysis'] = {
                'analysis': f"Matched confirmed phishing pattern: {rule}",
                'model': 'rule-based',
                'timestamp': datetime.utcnow().isoformat(),
                'threat_level': 'HIGH',
                'confidence': 95,
                'decision': 'BLOCK',
                'rule': rule,
            }
            rule_hits += 1
        else:
            llm_queue.append(entry)
    if rule_hits:
        print(f"📏 {rule_hits} domain(s) decided by rules (no LLM call)")
        save_progress(feed, args.feed_file)

    to_analyze = llm_queue[:args.max_analyze]
    if len(llm_queue) > len(to_analyze):
        print(f"⏭️  {len(llm_queue) - len(to_analyze)} domain(s) left for the next run")

    if not to_analyze:
        print("✓ No domains need LLM analysis")
        write_stats({'analyzed_count': 0, 'high_confidence': 0, 'medium_confidence': 0,
                     'false_positives': 0, 'errors': 0, 'rule_based': rule_hits}, args.feed_file)
        return

    print(f"\n🔍 Analyzing {len(to_analyze)} domains with LLM...")
    print(f"   Model: {MODEL} (fallback {MODEL_FALLBACK}), one request every {MIN_REQUEST_INTERVAL:g}s")
    print(f"   Targets: Bulgarian couriers + MVR e-services + TollPass/Vinetki")
    print(f"   Limit: up to {args.max_analyze} domains this run\n")

    analyzer = GeminiAnalyzer(api_key)

    stats = {
        'analyzed_count': 0,
        'high_confidence': 0,
        'medium_confidence': 0,
        'false_positives': 0,
        'errors': 0,
        'rule_based': rule_hits,
    }

    consecutive_failures = 0
    for i, entry in enumerate(to_analyze, 1):
        domain = entry.get('domain', 'unknown')
        score = entry.get('score', 0)
        keywords = entry.get('keywords', [])

        print(f"[{i}/{len(to_analyze)}] Analyzing: {domain} (score: {score})")

        result = analyzer.analyze_domain(domain, score, keywords, entry)

        if result:
            consecutive_failures = 0
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
            consecutive_failures += 1
            print(f"   ❌ Analysis failed")

        if i % SAVE_EVERY == 0:
            save_progress(feed, args.feed_file)
            write_stats(stats, args.feed_file)
            print(f"   💾 Progress saved ({i}/{len(to_analyze)})")

        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            print(f"::warning::Stopping after {consecutive_failures} failures in a row "
                  f"(API quota/rate limit?). {len(to_analyze) - i} domains left for the next run.")
            break

    false_positive_domains, clean_feed, fp_file = save_progress(feed, args.feed_file)

    if false_positive_domains:
        print(f"\n🗑️  Removed {len(false_positive_domains)} false positive(s) from feed:")
        for fp in false_positive_domains:
            print(f"   - {fp['domain']}")
        print(f"   Saved to: {fp_file}")

    stats['false_positives'] = len(false_positive_domains)
    write_stats(stats, args.feed_file)

    print(f"\n{'='*60}")
    print(f"✓ Analysis Complete")
    print(f"{'='*60}")
    print(f"  Decided by rules:          {stats['rule_based']}")
    print(f"  Domains analyzed (LLM):    {stats['analyzed_count']}")
    print(f"  High confidence threats:   {stats['high_confidence']}")
    print(f"  Medium threats:            {stats['medium_confidence']}")
    print(f"  False positives removed:   {stats['false_positives']}")
    print(f"  Errors:                    {stats['errors']}")
    print(f"  Clean feed size:           {len(clean_feed)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
