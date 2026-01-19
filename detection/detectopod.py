import json
import logging
import datetime
import os
import sys
import time
import requests
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("cryptography module not available. Install with: pip install cryptography")


# Usage: python detectopod.py [--duration SECONDS] [--mode stream|poll] [--sources crtsh google cloudflare]

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
        'type': 'aggregator',
        'enabled': True
    },
    'google_argon2025h2': {
        'url': 'https://ct.googleapis.com/logs/us1/argon2025h2',
        'type': 'ct_log',
        'description': 'Google Argon2025h2 log'
    },
    'google_argon2026h1': {
        'url': 'https://ct.googleapis.com/logs/us1/argon2026h1',
        'type': 'ct_log',
        'description': 'Google Argon2026h1 log'
    },
    'google_argon2026h2': {
        'url': 'https://ct.googleapis.com/logs/us1/argon2026h2',
        'type': 'ct_log',
        'description': 'Google Argon2026h2 log'
    },
    'cloudflare_nimbus2025': {
        'url': 'https://ct.cloudflare.com/logs/nimbus2025',
        'type': 'ct_log',
        'description': 'Cloudflare Nimbus2025'
    },
    'cloudflare_nimbus2026': {
        'url': 'https://ct.cloudflare.com/logs/nimbus2026',
        'type': 'ct_log',
        'description': 'Cloudflare Nimbus2026'
    },
    'cloudflare_nimbus2027': {
        'url': 'https://ct.cloudflare.com/logs/nimbus2027',
        'type': 'ct_log',
        'description': 'Cloudflare Nimbus2027'
    }
}

OUTPUT_FILE = 'feed/phishing_feed.json'
STATS_FILE = 'feed/stats.json'
START_TIME = None
MAX_DURATION = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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


def save_run_stats(certs_analyzed, domains_processed, new_findings, elapsed_time):
    """Save run statistics to a file for GitHub Actions summary"""
    stats_file = os.path.join(os.path.dirname(OUTPUT_FILE), 'run_stats.json')
    
    stats = {
        "certs_analyzed": certs_analyzed,
        "domains_processed": domains_processed,
        "new_findings": new_findings,
        "elapsed_time": round(elapsed_time, 1),
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    try:
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        logging.info(f"Run stats saved to {stats_file}")
    except Exception as e:
        logging.error(f"Error saving run stats: {e}")


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



def extract_domains_from_cert(cert_data):
    """Extract all domain names from a certificate"""
    if not CRYPTOGRAPHY_AVAILABLE:
        return []

    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        domains = []

        # Get Common Name
        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            domains.append(cn)
        except:
            pass

        # Get Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    domains.append(san.value)
        except:
            pass

        return domains
    except Exception as e:
        logging.debug(f"Error extracting domains from cert: {e}")
        return []


def query_ct_log_direct(log_url, max_entries=500):
    """Query a CT log directly using RFC 6962 API"""
    try:
        # Get the current tree size
        sth_url = f"{log_url}/ct/v1/get-sth"
        response = requests.get(sth_url, timeout=10)

        if response.status_code != 200:
            logging.warning(f"Failed to get STH from {log_url}: {response.status_code}")
            return []

        tree_size = response.json().get('tree_size', 0)

        if tree_size == 0:
            return []

        # Get recent entries (last max_entries)
        start = max(0, tree_size - max_entries)
        end = min(start + max_entries - 1, tree_size - 1)

        entries_url = f"{log_url}/ct/v1/get-entries?start={start}&end={end}"
        response = requests.get(entries_url, timeout=30)

        if response.status_code != 200:
            logging.warning(f"Failed to get entries from {log_url}: {response.status_code}")
            return []

        entries_data = response.json().get('entries', [])
        results = []

        for entry in entries_data:
            try:
                # Decode the extra_data which contains the certificate chain
                extra_data = base64.b64decode(entry['extra_data'])

                # Parse the certificate
                if len(extra_data) > 3:
                    # Read certificate length (3 bytes, big-endian)
                    cert_len = int.from_bytes(extra_data[0:3], 'big')
                    cert_data = extra_data[3:3+cert_len]

                    # Convert DER to PEM
                    pem_cert = b'-----BEGIN CERTIFICATE-----\n'
                    pem_cert += base64.b64encode(cert_data)
                    pem_cert += b'\n-----END CERTIFICATE-----\n'

                    # Extract domains
                    domains = extract_domains_from_cert(pem_cert)

                    for domain in domains:
                        results.append({
                            'name_value': domain,
                            'source': log_url
                        })
            except Exception as e:
                logging.debug(f"Error parsing CT log entry: {e}")
                continue

        logging.info(f"Retrieved {len(results)} certificates from {log_url}")
        return results

    except requests.exceptions.Timeout:
        logging.warning(f"Timeout querying {log_url}")
        return []
    except Exception as e:
        logging.error(f"Error querying CT log {log_url}: {e}")
        return []


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
    logging.info(f"Monitoring {len(TARGET_SUFFIXES)} target suffixes")

    # Determine which query tasks to run
    query_tasks = []

    if 'crtsh' in sources and CT_LOG_SOURCES['crtsh']['enabled']:
        # crt.sh: query each suffix
        for suffix in TARGET_SUFFIXES:
            query_tasks.append(('crt.sh', suffix, lambda s=suffix: query_crtsh(s)))

    # Add Google CT logs
    if 'google' in sources:
        if not CRYPTOGRAPHY_AVAILABLE:
            logging.error("Cannot use Google CT logs: cryptography module not installed")
            logging.error("Install with: pip install cryptography")
        else:
            for log_key, log_info in CT_LOG_SOURCES.items():
                if log_key.startswith('google_') and log_info.get('type') == 'ct_log':
                    query_tasks.append((f"Google-{log_key}", log_info['url'], 
                                      lambda url=log_info['url']: query_ct_log_direct(url, max_entries=500)))

    # Add Cloudflare CT logs  
    if 'cloudflare' in sources:
        if not CRYPTOGRAPHY_AVAILABLE:
            logging.error("Cannot use Cloudflare CT logs: cryptography module not installed")
            logging.error("Install with: pip install cryptography")
        else:
            for log_key, log_info in CT_LOG_SOURCES.items():
                if log_key.startswith('cloudflare_') and log_info.get('type') == 'ct_log':
                    query_tasks.append((f"Cloudflare-{log_key}", log_info['url'],
                                      lambda url=log_info['url']: query_ct_log_direct(url, max_entries=500)))

    if not query_tasks:
        logging.error("No CT log sources enabled!")
        return

    logging.info(f"Prepared {len(query_tasks)} query tasks")

    # Execute queries with thread pool
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_task = {}

        for source_name, target, query_func in query_tasks:
            future = executor.submit(query_func)
            future_to_task[future] = (source_name, target)

        for future in as_completed(future_to_task):
            source_name, target = future_to_task[future]

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

                    # Check if domain matches our target suffixes
                    matches_suffix = any(domain.endswith(suffix) for suffix in TARGET_SUFFIXES)

                    if matches_suffix:
                        # Calculate suspicion score
                        score = calculate_score(domain)

                        if score >= SCORE_THRESHOLD:
                            findings_count += 1
                            logging.warning(f"[SUSPICIOUS] {domain} (score: {score}) from {source_name}")

                            # Add to feed
                            entry = {
                                'domain': domain,
                                'score': score,
                                'source': source_name,
                                'cert_data': cert
                            }
                            add_to_feed(entry)
                        else:
                            logging.info(f"[OK] {domain} (score: {score})")

            except Exception as e:
                logging.error(f"Error processing results from {source_name}/{target}: {e}")

    # Save final stats
    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    save_run_stats(len(processed_domains), findings_count, elapsed, 0)

    logging.info(f"Polling complete. Processed {len(processed_domains)} domains, found {findings_count} suspicious.")


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
                       help='Mode: stream (certstream), poll (CT logs), auto (try stream, fallback to poll)')
    parser.add_argument('--sources', nargs='+', choices=['crtsh', 'google', 'cloudflare'], 
                       default=['crtsh'],
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
