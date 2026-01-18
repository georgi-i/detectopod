import certstream
import json
import logging
import datetime
import os
import sys


# Usage: python detectopod.py

# Configuration
KEYWORDS = [
    'econt', 'speedy', 'bulgariapost', 'bgpost',
    'tracking', 'delivery', 'shipment', 'parcel',
    'payment', 'secure-pay', 'tax', 'fee',
    'customer-center', 'klient', 'pratka'
]

TARGET_SUFFIXES = (
    '.web.app',
    '.firebaseapp.com',
    '.herokuapp.com',
    '.pages.dev',
    '.netlify.app',
    '.vercel.app',
    '.onrender.com',
    '.render.com',
    '.fly.dev',
    '.surge.sh',
    '.gitlab.io',
    '.github.io',
    '.repl.co',
    '.replit.dev',
    '.replit.app',
    '.glitch.me',
    '.amazonaws.com',
    '.elasticbeanstalk.com',
    '.azurewebsites.net',
    '.cloudapp.net',
    '.windows.net',
    '.azure-api.net'
)

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'feed.json')

logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(message)s', level=logging.INFO)


def load_existing_feed():
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []


def save_feed(feed_data):
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(feed_data, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving feed: {e}")


def calculate_score(domain):
    score = 0
    domain_lower = domain.lower()

    # Base score for target platforms
    for suffix in TARGET_SUFFIXES:
        if domain_lower.endswith(suffix):
            score += 50
            break

    if score == 0:
        return 0  # Not interest

    # Keyword scoring
    for keyword in KEYWORDS:
        if keyword in domain_lower:
            score += 20

    # Penalize known legit subdomains if necessary (whitelist) - skipped for now

    return score


# Global start time for timeout handling
START_TIME = None
MAX_DURATION = None


def process_message(message, context):
    # Check for timeout
    if MAX_DURATION and START_TIME:
        if (datetime.datetime.now() - START_TIME).total_seconds() > MAX_DURATION:
            logging.info(f"Max duration of {MAX_DURATION}s reached. Exiting.")
            sys.exit(0)

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            # Check if relevant platform
            is_target_platform = False
            for suffix in TARGET_SUFFIXES:
                if domain.endswith(suffix):
                    is_target_platform = True
                    break

            if not is_target_platform:
                continue

            score = calculate_score(domain)

            # Threshold for alert
            if score >= 70:  # 50 (platform) + 20 (at least one keyword)
                logging.info(f"SUSPICIOUS DOMAIN FOUND: {domain} (Score: {score})")

                feed = load_existing_feed()

                # Check for duplicates
                if any(entry['domain'] == domain for entry in feed):
                    continue

                new_entry = {
                    "domain": domain,
                    "score": score,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "status": "active",  # could be 'active', 'verified', etc.
                    "source": "CertStream"
                }

                feed.insert(0, new_entry)  # Add to top

                # Keep only last 100
                if len(feed) > 100:
                    feed = feed[:100]

                save_feed(feed)


def main():
    global START_TIME, MAX_DURATION

    import argparse
    parser = argparse.ArgumentParser(description='Phishing Domain Detector')
    parser.add_argument('--duration', type=int, help='Run for N seconds and then exit', default=None)
    args = parser.parse_args()

    MAX_DURATION = args.duration
    START_TIME = datetime.datetime.now()

    logging.info("Starting Phishing Domain Detector...")
    logging.info(f"Monitoring output to: {OUTPUT_FILE}")

    if MAX_DURATION:
        logging.info(f"Running for {MAX_DURATION} seconds.")

    # Ensure output dir exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Create empty feed if not exists
    if not os.path.exists(OUTPUT_FILE):
        save_feed([])

    certstream.listen_for_events(process_message, url='wss://certstream.calidog.io/')


if __name__ == "__main__":
    main()
