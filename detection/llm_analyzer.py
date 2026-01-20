#!/usr/bin/env python3
"""
LLM-based phishing domain analyzer
Analyzes domains from feed using OpenRouter API
"""

import json
import os
import sys
import time
import argparse
import requests
from datetime import datetime, timedelta

class OpenRouterAnalyzer:
    def __init__(self, api_key, model="meta-llama/llama-3.3-70b-instruct:free"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.requests_made = 0
        self.max_requests = 50  # Free tier daily limit

    def analyze_domain(self, domain, score, keywords_found, cert_info):
        """Analyze a domain using LLM"""
        if self.requests_made >= self.max_requests:
            print(f"⚠️  Daily limit reached ({self.max_requests} requests)")
            return None

        prompt = f"""Analyze this potential phishing domain:

Domain: {domain}
Rule-based Score: {score}/100
Keywords: {', '.join(keywords_found) if keywords_found else 'None'}
Hosting: Free/serverless platform
Target: Bulgarian courier services (Econt, Speedy, BulgariaPost)

Provide structured analysis:
1. Threat Level: HIGH/MEDIUM/LOW
2. Confidence: 0-100%
3. Key Indicators: List 2-3 specific red flags
4. Decision: BLOCK/INVESTIGATE/FALSE_POSITIVE

Be concise. Focus on domain patterns typical of phishing."""

        try:
            response = requests.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "HTTP-Referer": "https://github.com/detectopod",
                    "X-Title": "Phishing Detector"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Be concise."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 300
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                analysis = result['choices'][0]['message']['content']
                self.requests_made += 1

                # Add 3-second delay to respect rate limits (20/minute)
                time.sleep(3)

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
    parser.add_argument('--max-analyze', type=int, default=50, help='Maximum domains to analyze')
    parser.add_argument('--min-score', type=int, default=75, help='Minimum score to analyze')
    parser.add_argument('--feed-file', default='feed/phishing_feed.json', help='Feed file path')
    args = parser.parse_args()

    # Get API key from environment
    api_key = os.environ.get('OPENROUTER_API_KEY')
    if not api_key:
        print("❌ Error: OPENROUTER_API_KEY environment variable not set")
        sys.exit(1)

    # Load feed
    if not os.path.exists(args.feed_file):
        print(f"❌ Feed file not found: {args.feed_file}")
        sys.exit(1)

    with open(args.feed_file, 'r') as f:
        feed = json.load(f)

    # Filter domains to analyze
    cutoff_date = datetime.now() - timedelta(days=args.days)
    to_analyze = []

    for entry in feed:
        # Skip if already analyzed
        if 'llm_analysis' in entry:
            continue

        # Check score threshold
        if entry.get('score', 0) < args.min_score:
            continue

        # Check date (if available)
        entry_date_str = entry.get('discovered_date') or entry.get('first_seen')
        if entry_date_str:
            try:
                entry_date = datetime.fromisoformat(entry_date_str.replace('Z', '+00:00'))
                if entry_date < cutoff_date:
                    continue
            except:
                pass

        to_analyze.append(entry)

    # Limit to max_analyze
    to_analyze = sorted(to_analyze, key=lambda x: x.get('score', 0), reverse=True)[:args.max_analyze]

    if not to_analyze:
        print("✓ No domains need analysis")
        return

    print(f"\n🔍 Analyzing {len(to_analyze)} domains with LLM...")
    print(f"   Model: Llama 3.3 70B")
    print(f"   Limit: {args.max_analyze} domains\n")

    # Initialize analyzer
    analyzer = OpenRouterAnalyzer(api_key)

    # Analyze domains
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

            # Update stats
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

    # Save updated feed
    with open(args.feed_file, 'w') as f:
        json.dump(feed, f, indent=2)

    # Save stats
    stats['timestamp'] = datetime.utcnow().isoformat()
    stats_file = os.path.join(os.path.dirname(args.feed_file), 'llm_analysis_stats.json')
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)

    # Print summary
    print(f"\n{'='*60}")
    print(f"✓ Analysis Complete")
    print(f"{'='*60}")
    print(f"  Domains analyzed: {stats['analyzed_count']}")
    print(f"  High confidence threats: {stats['high_confidence']}")
    print(f"  Medium threats: {stats['medium_confidence']}")
    print(f"  False positives identified: {stats['false_positives']}")
    print(f"  Errors: {stats['errors']}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
