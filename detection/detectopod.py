import json
import logging
import datetime
import os
import sys
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


# Usage: python detectopod.py [--duration SECONDS] [--mode stream|poll]

# Configuration
SCORE_THRESHOLD = 80

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

# CT Log URLs for direct polling
CT_LOG_SOURCES = {
    'crtsh': {
        'name': 'crt.sh',
        'enabled': True
    }
}

# CertStream URLs (for streaming mode)
CT_STREAMS = [
    'wss://certstream.calidog.io/',
    'wss://certstream-v2.calidog.io/',
]

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
        logging.info(f"Feed saved with {len(feed_data)} entries")
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
        return 0  # Not interesting

    # Keyword scoring
    for keyword in KEYWORDS:
        if keyword in domain_lower:
            score += 20

    return score


def add_to_feed(domain, score):
    """Add a suspicious domain to the feed"""
    feed = load_existing_feed()

    # Check for duplicates
    if any(entry['domain'] == domain for entry in feed):
        return False

    new_entry = {
        "domain": domain,
        "score": score,
        "timestamp": datetime.datetime.now().isoformat(),
        "status": "active",
        "source": "CT Logs"
    }

    feed.insert(0, new_entry)  # Add to top

    # Keep only last 100
    if len(feed) > 100:
        feed = feed[:100]

    save_feed(feed)
    return True


# ==================== POLLING MODE (Direct CT Log Access) ====================

def query_crtsh(suffix, max_results=1000, retry_count=0, max_retries=2):
    """Query crt.sh for certificates matching a specific suffix"""
    try:
        # Search for domains ending with the suffix
        search_query = f"%25.{suffix.lstrip('.')}"
        url = f"https://crt.sh/?q={search_query}&output=json"
        
        logging.info(f"Querying crt.sh for: {suffix}")
        response = requests.get(url, timeout=45)
        
        if response.status_code == 200:
            data = response.json()
            logging.info(f"Found {len(data)} certificates for {suffix}")
            return data[:max_results]
        elif response.status_code == 503:
            # Service unavailable - retry with backoff
            if retry_count < max_retries:
                wait_time = (retry_count + 1) * 3
                logging.warning(f"crt.sh returned 503 for {suffix}, retrying in {wait_time}s (attempt {retry_count + 1}/{max_retries})")
                time.sleep(wait_time)
                return query_crtsh(suffix, max_results, retry_count + 1, max_retries)
            else:
                logging.error(f"crt.sh returned 503 for {suffix} after {max_retries} retries, skipping")
                return []
        else:
            logging.warning(f"crt.sh returned status {response.status_code} for {suffix}")
            return []
    except requests.exceptions.Timeout:
        # Timeout - retry with longer timeout
        if retry_count < max_retries:
            wait_time = (retry_count + 1) * 3
            logging.warning(f"Timeout querying crt.sh for {suffix}, retrying in {wait_time}s (attempt {retry_count + 1}/{max_retries})")
            time.sleep(wait_time)
            return query_crtsh(suffix, max_results, retry_count + 1, max_retries)
        else:
            logging.error(f"Timeout querying crt.sh for {suffix} after {max_retries} retries, skipping")
            return []
    except Exception as e:
        logging.error(f"Error querying crt.sh for {suffix}: {e}")
        return []





def poll_ct_logs(duration=None, sources=['crtsh']):
    """Poll CT logs directly via multiple sources"""
    start_time = datetime.datetime.now()
    processed_domains = set()
    findings_count = 0
    
    logging.info("Starting CT log polling mode...")
    logging.info(f"Using sources: {', '.join(sources)}")
    logging.info(f"Querying {len(TARGET_SUFFIXES)} target suffixes")
    
    # Determine which query function to use for each source
    query_functions = []
    
    if 'crtsh' in sources and CT_LOG_SOURCES['crtsh']['enabled']:
        query_functions.append(('crt.sh', query_crtsh))
    
    if not query_functions:
        logging.error("No CT log sources enabled!")
        return
    
    # Query each source
    for source_name, query_func in query_functions:
        logging.info(f"Querying {source_name}...")
        
        # Use ThreadPoolExecutor to query multiple suffixes in parallel
        # Reduced workers to 3 to avoid overwhelming crt.sh
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit queries for all suffixes
            future_to_suffix = {
                executor.submit(query_func, suffix): suffix 
                for suffix in TARGET_SUFFIXES
            }
            
            for future in as_completed(future_to_suffix):
                suffix = future_to_suffix[future]
                
                # Check timeout
                if duration:
                    elapsed = (datetime.datetime.now() - start_time).total_seconds()
                    if elapsed > duration:
                        logging.info(f"Duration limit reached. Processed {len(processed_domains)} domains, found {findings_count} suspicious.")
                        return
                
                try:
                    results = future.result()
                    
                    for cert in results:
                        # Extract domain name
                        domain = cert.get('name_value', '').strip()
                        
                        if not domain or domain in processed_domains:
                            continue
                        
                        processed_domains.add(domain)
                        
                        # Skip wildcards
                        if domain.startswith('*'):
                            continue
                        
                        # Calculate score
                        score = calculate_score(domain)
                        
                        if score >= SCORE_THRESHOLD:
                            logging.info(f"SUSPICIOUS DOMAIN FOUND: {domain} (Score: {score}, Source: {source_name})")
                            if add_to_feed(domain, score):
                                findings_count += 1
                                
                except Exception as e:
                    logging.error(f"Error processing results for {suffix} from {source_name}: {e}")
    
    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    logging.info(f"Polling completed in {elapsed:.1f}s. Processed {len(processed_domains)} domains, found {findings_count} suspicious.")


# ==================== STREAMING MODE (CertStream) ====================

START_TIME = None
MAX_DURATION = None
STREAM_CONNECTED = False
DOMAINS_PROCESSED = 0


def process_message(message, context):
    """Process certstream messages"""
    global STREAM_CONNECTED, DOMAINS_PROCESSED
    
    # Check for timeout
    if MAX_DURATION and START_TIME:
        if (datetime.datetime.now() - START_TIME).total_seconds() > MAX_DURATION:
            logging.info(f"Max duration of {MAX_DURATION}s reached. Processed {DOMAINS_PROCESSED} domains. Exiting.")
            sys.exit(0)

    if message['message_type'] == "heartbeat":
        if not STREAM_CONNECTED:
            logging.info("Stream connected and receiving heartbeats")
            STREAM_CONNECTED = True
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        DOMAINS_PROCESSED += len(all_domains)

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

            if score >= SCORE_THRESHOLD:
                logging.info(f"SUSPICIOUS DOMAIN FOUND: {domain} (Score: {score})")
                add_to_feed(domain, score)


def try_connect_stream(url, timeout=10):
    """Try to connect to a CT stream with a timeout"""
    try:
        import certstream
    except ImportError:
        logging.error("certstream library not installed. Install with: pip install certstream")
        return False
    
    import threading
    global STREAM_CONNECTED
    
    connection_successful = threading.Event()
    
    def connect_thread():
        try:
            logging.info(f"Attempting to connect to: {url}")
            certstream.listen_for_events(
                process_message, 
                url=url,
                skip_heartbeats=False
            )
        except Exception as e:
            logging.error(f"Error in stream connection: {e}")
    
    # Start connection in a thread
    thread = threading.Thread(target=connect_thread, daemon=True)
    thread.start()
    
    # Wait for connection or timeout
    logging.info(f"Waiting {timeout}s for stream connection...")
    time.sleep(timeout)
    
    if STREAM_CONNECTED:
        logging.info("Stream connected successfully!")
        # Let the thread continue running
        thread.join()
        return True
    else:
        logging.warning(f"Stream connection timeout after {timeout}s")
        return False


def run_stream_mode(connection_timeout=10):
    """Run in streaming mode using certstream"""
    global START_TIME, MAX_DURATION, STREAM_CONNECTED
    
    # Try each CT stream until one works (with quick timeout)
    for stream_url in CT_STREAMS:
        logging.info(f"Trying CT stream: {stream_url}")
        
        if try_connect_stream(stream_url, timeout=connection_timeout):
            logging.info(f"Successfully connected to {stream_url}")
            return True
        else:
            logging.warning(f"Failed to connect to {stream_url}, trying next...")
            STREAM_CONNECTED = False  # Reset for next attempt
            
    # No streams worked
    logging.error("All CT streams failed.")
    return False


# ==================== MAIN ====================

def main():
    global START_TIME, MAX_DURATION

    import argparse
    parser = argparse.ArgumentParser(description='Phishing Domain Detector')
    parser.add_argument('--duration', type=int, help='Run for N seconds and then exit', default=None)
    parser.add_argument('--mode', choices=['stream', 'poll', 'auto'], default='auto',
                       help='Mode: stream (certstream), poll (crt.sh), auto (try stream, fallback to poll)')
    parser.add_argument('--sources', nargs='+', choices=['crtsh'], default=['crtsh'],
                       help='CT log sources to use in poll mode (default: crtsh only)')
    args = parser.parse_args()

    MAX_DURATION = args.duration
    START_TIME = datetime.datetime.now()

    logging.info("Starting Phishing Domain Detector...")
    logging.info(f"Mode: {args.mode}")
    logging.info(f"Monitoring output to: {OUTPUT_FILE}")

    if MAX_DURATION:
        logging.info(f"Running for {MAX_DURATION} seconds.")

    # Ensure output dir exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # Create empty feed if not exists
    if not os.path.exists(OUTPUT_FILE):
        save_feed([])

    # Choose mode
    if args.mode == 'poll':
        poll_ct_logs(duration=MAX_DURATION, sources=args.sources)
    elif args.mode == 'stream':
        if not run_stream_mode(connection_timeout=10):
            logging.error("Streaming mode failed. Exiting.")
            sys.exit(1)
    else:  # auto mode
        logging.info("Auto mode: Trying stream first (10s timeout), will fallback to polling if needed")
        if not run_stream_mode(connection_timeout=10):
            logging.warning("Streaming failed, falling back to polling mode...")
            poll_ct_logs(duration=MAX_DURATION, sources=args.sources)


if __name__ == "__main__":
    main()
