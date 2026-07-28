import json
import logging
import datetime
import os
import sys
import time
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Usage: python detectopod.py [--duration SECONDS] [--sources urlscan google cloudflare]

# Configuration
SCORE_THRESHOLD = 80

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")

if not URLSCAN_API_KEY:
    logging.error("URLSCAN_API_KEY environment variable is not set. API calls will fail.")

# PRIMARY TARGET: Bulgarian courier/logistics companies
COURIER_KEYWORDS = [
    'econt',
    'speedy', 
    'bulgariapost',
    'bgpost',
    'bg-post',
    'samedaybg',
    'boxnowbg',
    'cityexpressbg',
    'expressonebg',
    'dhl',           # DHL Bulgaria
    # Bulgarian government e-services
    'mvr',           # Ministry of Interior (MVR - Министерство на вътрешните работи)
    'mvrbg',         # MVR Bulgaria combined form (e.g. mvrbg.sbs)
    'mvr-bg',        # MVR Bulgaria hyphenated form (e.g. mvr-bg.cfd, mvr-bg.top, mvr-bg.ink)
    'mvr-gov',       # MVR government pattern (e.g. mvr-gov-mk.shop, mvr-gov-mk.cyou)
    'e-uslugi',      # E-services portal (e-uslugi.mvr.bg)
    'euslugi',       # Without-hyphen variant
    # Bulgarian toll/vignette payment services
    'tollpass',      # TollPass (tollpass.bg) - e.g. tollpass.klgf.cam, tollpassapp.top, tollpassss.cc
    'vinetki',       # Vinetki.bg - sister brand of TollPass (toll vignette service)
]

# SECONDARY: Generic logistics/delivery terms (lower priority)
SECONDARY_KEYWORDS = [
    'tracking',
    'delivery', 
    'shipment',
    'parcel',
    'payment',
    'secure-pay',
    'tax',
    'fee',
    'customer-center',
    'klient',
    'pratka'
]

# Combined for backward compatibility with calculate_score
KEYWORDS = COURIER_KEYWORDS + SECONDARY_KEYWORDS

# Legitimate Bulgarian courier brands (for impersonation detection)
BULGARIAN_COURIER_BRANDS = [
    'econt',
    'speedy',
    'bulgariapost',
    'bgpost',
    'bg-post',
    'samedaybg',
    'boxnowbg',
    'cityexpressbg',
    'expressonebg'
]

# Bulgarian government brands (for impersonation detection)
# Legitimate site: e-uslugi.mvr.bg
BULGARIAN_GOVT_BRANDS = [
    'mvr',        # Ministry of Interior — appears as subdomain/prefix (mvr.bggov.cam, mvr-bg.shop)
    'mvrbg',      # Concatenated form (mvrbg.sbs, gav.mvrbg.cam, mvrbg.life, mvrbg.ink)
    'mvr-bg',     # Hyphenated form (mvr-bg.cfd, mvr-bg.shop, mvr-bg.sbs, mvr-bg.top)
    'e-uslugi',   # E-services portal — may appear with random suffix (e-uslugicye.top)
    'euslugi',    # Without-hyphen variant
    'mvr-gov',    # Government subdomain pattern (mvr-gov-mk.shop, mvr-gov-mk.icu, mvr-gov-mk.cyou)
]

# Bulgarian toll/vignette payment brands (for impersonation detection)
# Legitimate sites: tollpass.bg, vinetki.bg (operated by Intelligentni Trafik Sistemi AD)
BULGARIAN_TOLL_BRANDS = [
    'tollpass',   # TollPass — appears with random suffix (tollpass.klgf.cam, tollpassapp.top,
                  # tollpassss.cc, tollpass.dvhl.cam, tollpass.isxd.cam)
    'vinetki',    # Vinetki.bg — sister brand referenced on the legitimate site's footer
]

# Brands that are common English words or short acronyms appearing in many
# unrelated domains. For these, a Bulgarian geo indicator must also be present
# somewhere in the domain before we treat it as a phishing candidate.
#   speedy  — common English adjective (speedy.brtv.uno, speedy-glass.cfd)
#   dhl     — international brand used globally, not specific to Bulgaria
#   mvr     — 3-letter acronym found inside random strings (fumvrak, shumvrax)
# Unambiguous brands (econt, bgpost, mvrbg, mvr-bg, mvr-gov, e-uslugi …)
# do NOT need this check — they are specific enough on their own.
AMBIGUOUS_BRANDS = frozenset({'speedy', 'dhl', 'mvr', 'vinetki'})

# Geographic indicators that suggest impersonation
GEO_INDICATORS = ['.bg', 'bulgaria', 'bg-', '-bg', 'bggov', 'govbg', 'gov-bg', 'bg-gov']

# Suspicious/Free TLDs commonly used in phishing
SUSPICIOUS_TLDS = (
    '.cfd',      # Cloudflare - free, commonly abused 
    '.tk',       # Tokelau - free 
    '.ml',       # Mali - free 
    '.ga',       # Gabon - free 
    '.cf',       # Central African Republic - free 
    '.gq',       # Equatorial Guinea - free 
    '.top',      # Cheap, popular with phishers 
    '.xyz',      # Cheap 
    '.club',     # Cheap 
    '.online',   # Commonly abused 
    '.site',     # Commonly abused 
    '.space',    # Commonly abused 
    '.click',    # Red flag for phishing 
    '.link',     # Red flag 
    '.live',     # Commonly abused 
    '.icu',      # Cheap
    '.sbs',      # Commonly abused for phishing
    '.cam',      # Cheap, commonly abused
    '.shop',     # Cheap, commonly abused
    '.one',      # Cheap, commonly abused
    '.autos',    # Used in government impersonation campaigns
    '.life',     # Cheap, commonly abused
    '.qpon',     # Coupon-related, abused for delivery scams
    '.uno',      # Cheap, commonly abused
    '.ink',      # Cheap, abused for government impersonation (mvrbg.ink)
    '.cyou',     # Cheap, abused for government impersonation (mvr-gov-mk.cyou)
    '.cc',       # Cheap, cocos-islands ccTLD abused for brand impersonation (tollpassss.cc)
)
# Free/serverless hosting platforms
FREE_HOSTING_SUFFIXES = (
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

# Combined - all suspicious patterns to monitor
TARGET_SUFFIXES = FREE_HOSTING_SUFFIXES + SUSPICIOUS_TLDS

# Infrastructure patterns to EXCLUDE (not customer domains)
INFRASTRUCTURE_PATTERNS = (
    # Render.com internal services
    '.postgres.render.com',
    '.redis.render.com',
    '.internal.render.com',
    'replica-',
    
    # AWS internal services - EXPANDED
    '.rds.amazonaws.com',
    '.elb.amazonaws.com',
    '.elasticache.amazonaws.com',
    '.drive.amazonaws.com',           # Amazon Drive
    'kms.amazonaws.com',              # AWS KMS
    'kms-a.', 'kms-b.', 'kms-c.',     # KMS endpoints
    'kms-d.', 'kms-e.', 'kms-f.',
    's3.amazonaws.com',               # S3 infrastructure
    's3-deprecated',                  # Deprecated S3
    'content-eu.drive',               # Drive content
    'content-jp.drive',
    'cnt-00.', 'cnt-01.', 'cnt-02.', 'cnt-03.',  # Content nodes
    
    # Azure internal
    '.database.windows.net',
    '.redis.cache.windows.net',
    
    # Cloudflare internal
    '.workers.dev',
    
    # Netlify/Vercel deployment previews
    '--deploy-preview-',
    'preview.vercel.app',
)

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


def add_to_feed(domain, score, source='urlscan'):
    """Add a suspicious domain to the feed"""
    feed_data = load_existing_feed()
    
    # Check if already in feed
    for entry in feed_data:
        if entry['domain'] == domain:
            logging.debug(f"Domain {domain} already in feed")
            return
    
    entry = {
        'domain': domain,
        'score': score,
        'detected_at': datetime.datetime.now().isoformat(),
        'source': source
    }
    
    feed_data.append(entry)
    save_feed(feed_data)


def calculate_score(domain):
    """
    Calculate suspicion score for a domain (0-100).
    Detects courier brand impersonation (Econt, Speedy, BulgariaPost)
    AND government service impersonation (MVR e-uslugi portal).
    """
    score = 0
    domain_lower = domain.lower()

    # Remove 'www.' prefix if present
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]

    # --- BRAND IMPERSONATION DETECTION (HIGH PRIORITY) ---
    has_brand = False
    has_geo = False
    has_suspicious_tld = False
    has_free_hosting = False

    # Check for Bulgarian courier brand
    for brand in BULGARIAN_COURIER_BRANDS:
        if brand in domain_lower:
            has_brand = True
            score += 35  # Increased base score for brand presence
            break

    # Check for Bulgarian government brand (MVR / e-uslugi)
    # Use substring match — these appear concatenated (mvrbg, e-uslugicye)
    if not has_brand:
        for brand in BULGARIAN_GOVT_BRANDS:
            if brand in domain_lower:
                has_brand = True
                score += 40  # Slightly higher: MVR impersonation is unambiguous
                break

    # Check for Bulgarian toll/vignette brand (TollPass / Vinetki)
    # Use substring match — catches concatenated variants (tollpassapp, tollpassss)
    if not has_brand:
        for brand in BULGARIAN_TOLL_BRANDS:
            if brand in domain_lower:
                has_brand = True
                score += 40  # Unambiguous brand presence
                break

    # Check for geographic indicators
    for geo in GEO_INDICATORS:
        if geo in domain_lower:
            has_geo = True
            score += 15  # Geographic indicator suggests impersonation
            break

    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            has_suspicious_tld = True
            score += 30  # Increased - suspicious TLD is a strong signal
            break

    # Check for free hosting platforms
    for suffix in FREE_HOSTING_SUFFIXES:
        if domain_lower.endswith(suffix):
            has_free_hosting = True
            score += 25  # Free hosting is suspicious for courier/gov brands
            break

    # --- CRITICAL COMBINATIONS ---
    # Brand + geo + suspicious TLD = classic phishing (e.g., econt.bg-g63829.cfd, mvrbg.sbs)
    if has_brand and has_geo and has_suspicious_tld:
        score += 45  # Maximum boost for this combo

    # Brand + suspicious TLD (even without geo)
    if has_brand and has_suspicious_tld:
        score += 25

    # Brand + free hosting = HIGHLY SUSPICIOUS
    if has_brand and has_free_hosting:
        score += 40  # Major boost - this is a key phishing indicator

    # Brand + geo + free hosting
    if has_brand and has_geo and has_free_hosting:
        score += 30

    # --- KEYWORD MATCHING ---
    keywords_found = []
    for keyword in KEYWORDS:
        if keyword in domain_lower:
            keywords_found.append(keyword)
            # Higher weight for primary brands
            if keyword in BULGARIAN_COURIER_BRANDS or keyword in BULGARIAN_GOVT_BRANDS or keyword in BULGARIAN_TOLL_BRANDS:
                score += 10
            else:
                score += 5

    # --- SUSPICIOUS PATTERNS ---
    # Multiple hyphens (often used to create fake subdomains like speedy-37a)
    hyphen_count = domain_lower.count('-')
    if hyphen_count >= 1:
        if has_brand:
            # Brand with hyphens is very suspicious
            score += hyphen_count * 8
        else:
            score += hyphen_count * 3

    # Mixed numbers and letters (e.g., speedy37a, econt24, g63829)
    if any(c.isdigit() for c in domain_lower) and any(c.isalpha() for c in domain_lower):
        if has_brand:
            # Brand + random numbers/letters = phishing pattern
            score += 15
        else:
            score += 8

    # Random-looking strings (e.g., g63829, 37a, e37)
    domain_name = domain_lower.split('.')[0]  # Get subdomain/domain part
    if re.search(r'[a-z]\d{2,}|\d{2,}[a-z]', domain_name):
        score += 12  # Random-looking identifier

    # Specific phishing patterns
    if 'verify' in domain_lower or 'confirm' in domain_lower:
        score += 15
    if 'secure' in domain_lower or 'account' in domain_lower:
        score += 15
    if 'update' in domain_lower or 'suspended' in domain_lower:
        score += 18
    if 'payment' in domain_lower or 'billing' in domain_lower:
        score += 15
    if 'login' in domain_lower or 'signin' in domain_lower:
        score += 15

    # --- LENGTH ANALYSIS ---
    domain_parts = domain_lower.split('.')
    if len(domain_parts[0]) > 20:  # Long subdomain/domain name
        score += 12

    # Cap score at 100
    score = min(score, 100)

    return score


def is_infrastructure_domain(domain):
    """
    Check if domain is infrastructure/internal service (not customer-facing)
    Returns True if domain should be EXCLUDED from scanning
    """
    domain_lower = domain.lower()
    
    # Check infrastructure patterns
    for pattern in INFRASTRUCTURE_PATTERNS:
        if pattern in domain_lower:
            return True
    
    # Render.com specific
    if 'render.com' in domain_lower:
        if 'postgres' in domain_lower or 'redis' in domain_lower:
            return True
    
    # AWS specific - expanded
    if '.amazonaws.com' in domain_lower:
        aws_internal = [
            '.rds.', '.elb.', '.elasticache.', '.vpc.', '.ec2.internal',
            'kms.', 'kms-', '.drive.', 's3.', 's3-', 'content-'
        ]
        if any(svc in domain_lower for svc in aws_internal):
            return True
    
    # Random/generic Cloudflare Pages projects (no brand keywords)
    if '.pages.dev' in domain_lower:
        has_brand, _ = contains_brand_keyword(domain_lower)
        if not has_brand:
            return True
    
    return False


def contains_brand_keyword(domain):
    """
    Alias for contains_courier_keyword — checks all monitored brands
    including government services. Used internally.
    """
    return contains_courier_keyword(domain)


def contains_courier_keyword(domain):
    """
    Check if domain contains any monitored brand keyword.
    Covers courier brands AND government service brands (MVR).

    Matching rules
    ──────────────
    Unambiguous brands (econt, bgpost, mvrbg, e-uslugi …):
      Substring match is fine — they are specific enough that a hit is always
      meaningful (e.g. mvrbg.sbs, e-uslugicye.top).

    Ambiguous brands (speedy, dhl, mvr — see AMBIGUOUS_BRANDS):
      These are common words / short acronyms that appear legitimately in many
      unrelated domains.  Two extra requirements apply:
        1. Label-boundary match: the keyword must sit at a domain-label boundary
           (preceded/followed by '.', '-', or start/end of string).
           This prevents 'mvr' matching inside 'fumvrak' or 'shumvrax'.
        2. Geo-indicator required: at least one Bulgarian geo token (.bg, bg-,
           -bg, bggov, govbg …) must also appear somewhere in the domain.
           This prevents 'speedy.brtv.uno' or 'mvr-retreat.life' from matching.

    Returns (has_keyword, matched_keywords)
    """
    domain_lower = domain.lower()
    # Strip leading www. for cleaner matching
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]

    matched = []

    # Pre-compute whether any Bulgarian geo indicator is present
    has_geo = any(geo in domain_lower for geo in GEO_INDICATORS)

    # --- Courier brands (word-boundary match) ---
    for keyword in COURIER_KEYWORDS:
        # Government and toll brands are handled separately below
        if keyword in BULGARIAN_GOVT_BRANDS or keyword in BULGARIAN_TOLL_BRANDS:
            continue

        if keyword in AMBIGUOUS_BRANDS:
            # Require both label-boundary match AND geo indicator
            if not has_geo:
                continue
            pattern = r'(?:^|[.\-])' + re.escape(keyword) + r'(?:[.\-]|$)'
        else:
            pattern = r'\b' + re.escape(keyword) + r'\b'

        if re.search(pattern, domain_lower):
            matched.append(keyword)

    # --- Government brands ---
    for brand in BULGARIAN_GOVT_BRANDS:
        if brand in matched:
            continue

        if brand in AMBIGUOUS_BRANDS:
            # e.g. plain 'mvr': require label-boundary + geo
            # catches mvr-bg.cfd, mvr.bggov.cam but not fumvrak.life
            if not has_geo:
                continue
            pattern = r'(?:^|[.\-])' + re.escape(brand) + r'(?:[.\-]|$)'
            if re.search(pattern, domain_lower):
                matched.append(brand)
        else:
            # Unambiguous (mvrbg, e-uslugi, euslugi): plain substring is fine
            if brand in domain_lower:
                matched.append(brand)

    # --- Toll/vignette brands (TollPass / Vinetki) ---
    for brand in BULGARIAN_TOLL_BRANDS:
        if brand in matched:
            continue

        if brand in AMBIGUOUS_BRANDS:
            # e.g. 'vinetki': require label-boundary + geo indicator
            if not has_geo:
                continue
            pattern = r'(?:^|[.\-])' + re.escape(brand) + r'(?:[.\-]|$)'
            if re.search(pattern, domain_lower):
                matched.append(brand)
        else:
            # Unambiguous (tollpass): plain substring — catches concatenated
            # variants like tollpassapp.top, tollpassss.cc, tollpass.klgf.cam
            if brand in domain_lower:
                matched.append(brand)

    # Special handling for DHL + Bulgaria combination
    if 'dhl' in domain_lower and has_geo:
        if 'dhl-bulgaria' not in matched:
            matched.append('dhl-bulgaria')

    return len(matched) > 0, matched


def save_run_stats(domains_scanned, phishing_found, elapsed_time):
    """Save run statistics to a file for GitHub Actions summary"""
    stats_dir = os.path.dirname(OUTPUT_FILE)
    if not stats_dir:
        stats_dir = 'feed'
    
    stats_file = os.path.join(stats_dir, 'run_stats.json')
    
    stats = {
        "domains_scanned": domains_scanned,
        "phishing_found": phishing_found,
        "elapsed_time": round(elapsed_time, 1),
        "timestamp": datetime.datetime.now().isoformat(),
        "last_run": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    
    try:
        os.makedirs(stats_dir, exist_ok=True)
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        logging.info(f"✓ Run stats saved to {stats_file}")
        logging.info(f"  Domains scanned: {domains_scanned}, Phishing found: {phishing_found}")
    except Exception as e:
        logging.error(f"Error saving run stats: {e}")


# ==================== URLSCAN.IO API INTEGRATION ====================


def query_urlscan(keywords, max_results=2000, retry_count=0, max_retries=2):
    """
    Query urlscan.io API for domains matching courier/government keywords
    """
    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        
        domain_queries = []
        for keyword in keywords:
            domain_queries.append(f'domain:*{keyword}*')
        
        page_queries = []
        for keyword in keywords:
            page_queries.append(f'page.domain:*{keyword}*')
        
        all_queries = domain_queries + page_queries
        search_query = ' OR '.join(all_queries)
        
        logging.info(f"Querying urlscan.io for brand keywords...")
        logging.debug(f"Query: {search_query[:300]}...")
        
        params = {
            'q': search_query,
            'size': min(max_results, 10000),
        }
        
        url = "https://urlscan.io/api/v1/search/"
        response = requests.get(url, headers=headers, params=params, timeout=45)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            total = data.get('total', 0)
            
            logging.info(f"Found {len(results)} results (total available: {total})")
            
            domains = []
            seen_domains = set()
            
            for result in results:
                domain = None
                
                if 'page' in result and 'domain' in result['page']:
                    domain = result['page']['domain']
                elif 'task' in result and 'domain' in result['task']:
                    domain = result['task']['domain']
                elif 'page' in result and 'url' in result['page']:
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(result['page']['url'])
                        domain = parsed.netloc
                    except:
                        pass
                
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    domains.append({
                        'domain': domain,
                        'url': result.get('page', {}).get('url', ''),
                        'scan_time': result.get('task', {}).get('time', ''),
                        'verdict': result.get('verdicts', {}).get('overall', {}).get('malicious', False),
                        'source': 'urlscan.io'
                    })
            
            logging.info(f"Extracted {len(domains)} unique domains")
            
            # Targeted TLD searches — covers both courier and government phishing TLDs
            if len(domains) < max_results * 0.8:
                logging.info("Performing targeted searches for suspicious TLDs...")
                
                tlds_to_search = [
                    '.cfd', '.tk', '.pages.dev', '.web.app', '.ml', '.ga',
                    '.sbs', '.cam', '.shop', '.one', '.autos', '.life',
                    '.qpon', '.uno', '.ink', '.cyou', '.top', '.icu', '.cc',
                ]
                for tld in tlds_to_search:
                    tld_query = ' OR '.join([f'domain:*{kw}*{tld}' for kw in keywords])
                    
                    tld_params = {
                        'q': tld_query,
                        'size': 500,
                    }
                    
                    try:
                        logging.debug(f"Searching {tld} domains...")
                        tld_response = requests.get(url, headers=headers, params=tld_params, timeout=30)
                        
                        if tld_response.status_code == 200:
                            tld_data = tld_response.json()
                            tld_results = tld_data.get('results', [])
                            
                            for result in tld_results:
                                domain = None
                                if 'page' in result and 'domain' in result['page']:
                                    domain = result['page']['domain']
                                elif 'task' in result and 'domain' in result['task']:
                                    domain = result['task']['domain']
                                
                                if domain and domain not in seen_domains:
                                    seen_domains.add(domain)
                                    domains.append({
                                        'domain': domain,
                                        'url': result.get('page', {}).get('url', ''),
                                        'scan_time': result.get('task', {}).get('time', ''),
                                        'verdict': result.get('verdicts', {}).get('overall', {}).get('malicious', False),
                                        'source': f'urlscan.io-{tld}'
                                    })
                            
                            logging.debug(f"  Found {len(tld_results)} on {tld}")
                        
                        time.sleep(0.5)
                        
                    except Exception as e:
                        logging.debug(f"Error searching {tld}: {e}")
                        continue
            
            logging.info(f"Total unique domains collected: {len(domains)}")
            return domains
            
        elif response.status_code == 429:
            if retry_count < max_retries:
                wait_time = (retry_count + 1) * 10
                logging.warning(f"Rate limited by urlscan.io, retrying in {wait_time}s")
                time.sleep(wait_time)
                return query_urlscan(keywords, max_results, retry_count + 1, max_retries)
            else:
                logging.error(f"Rate limited by urlscan.io after {max_retries} retries")
                return []
                
        elif response.status_code == 400:
            logging.error(f"Bad request to urlscan.io: {response.text}")
            return []
            
        else:
            logging.warning(f"urlscan.io returned status {response.status_code}: {response.text}")
            return []
            
    except requests.exceptions.Timeout:
        if retry_count < max_retries:
            wait_time = (retry_count + 1) * 5
            logging.warning(f"Timeout querying urlscan.io, retrying in {wait_time}s")
            time.sleep(wait_time)
            return query_urlscan(keywords, max_results, retry_count + 1, max_retries)
        else:
            logging.error(f"Timeout querying urlscan.io after {max_retries} retries")
            return []
            
    except Exception as e:
        logging.error(f"Error querying urlscan.io: {e}")
        return []


def query_urlscan_recent(days=7, max_results=1000):
    """
    Query urlscan.io for recent submissions containing brand keywords
    """
    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=days)
        
        keyword_query = ' OR '.join([f'page.domain:*{k}*' for k in COURIER_KEYWORDS])
        date_filter = f'date:>{start_date.strftime("%Y-%m-%d")}'
        full_query = f'({keyword_query}) AND {date_filter}'
        
        logging.info(f"Querying urlscan.io for last {days} days")
        
        params = {
            'q': full_query,
            'size': min(max_results, 10000),
        }
        
        url = "https://urlscan.io/api/v1/search/"
        response = requests.get(url, headers=headers, params=params, timeout=45)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            
            logging.info(f"Found {len(results)} recent submissions")
            
            domains = []
            seen_domains = set()
            
            for result in results:
                domain = None
                
                if 'page' in result and 'domain' in result['page']:
                    domain = result['page']['domain']
                elif 'task' in result and 'domain' in result['task']:
                    domain = result['task']['domain']
                
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    domains.append({
                        'domain': domain,
                        'url': result.get('page', {}).get('url', ''),
                        'scan_time': result.get('task', {}).get('time', ''),
                        'source': 'urlscan.io'
                    })
            
            return domains
        else:
            logging.warning(f"urlscan.io returned status {response.status_code}")
            return []
            
    except Exception as e:
        logging.error(f"Error querying recent urlscan submissions: {e}")
        return []


# ==================== CT LOG SOURCES (Google/Cloudflare) ====================

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("cryptography module not available. Install with: pip install cryptography")


CT_LOG_SOURCES = {
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


def extract_domains_from_cert(cert_data):
    """Extract all domain names from a certificate"""
    if not CRYPTOGRAPHY_AVAILABLE:
        return []

    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        domains = []

        try:
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            domains.append(cn)
        except:
            pass

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
        import base64
        
        sth_url = f"{log_url}/ct/v1/get-sth"
        response = requests.get(sth_url, timeout=10)

        if response.status_code != 200:
            logging.warning(f"Failed to get STH from {log_url}: {response.status_code}")
            return []

        tree_size = response.json().get('tree_size', 0)

        if tree_size == 0:
            return []

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
                extra_data = base64.b64decode(entry['extra_data'])

                if len(extra_data) > 3:
                    cert_len = int.from_bytes(extra_data[0:3], 'big')
                    cert_data = extra_data[3:3+cert_len]

                    pem_cert = b'-----BEGIN CERTIFICATE-----\n'
                    pem_cert += base64.b64encode(cert_data)
                    pem_cert += b'\n-----END CERTIFICATE-----\n'

                    domains = extract_domains_from_cert(pem_cert)

                    for domain in domains:
                        results.append({
                            'domain': domain,
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


# ==================== MAIN SCANNING LOGIC ====================


def scan_domains(duration=None, sources=['urlscan']):
    """
    Main scanning function using configured sources.
    Monitors both courier brands and government service brands (MVR).
    """
    start_time = datetime.datetime.now()
    processed_domains = set()
    findings_count = 0

    logging.info("Starting phishing domain scanner...")
    logging.info(f"Using sources: {', '.join(sources)}")
    logging.info(f"Score threshold: {SCORE_THRESHOLD}")
    logging.info(f"Monitoring: courier brands + MVR government services")

    all_domains = []

    # URLScan.io - PRIMARY SOURCE
    if 'urlscan' in sources:
        logging.info("=" * 60)
        logging.info("Querying URLScan.io...")
        logging.info("=" * 60)
        
        urlscan_domains = query_urlscan(COURIER_KEYWORDS, max_results=1000)
        all_domains.extend(urlscan_domains)
        
        logging.info(f"URLScan.io returned {len(urlscan_domains)} domains")
        
        recent_domains = query_urlscan_recent(days=7, max_results=500)
        all_domains.extend(recent_domains)
        
        logging.info(f"Recent submissions: {len(recent_domains)} domains")

    # Google CT Logs - SUPPLEMENTARY
    if 'google' in sources:
        if not CRYPTOGRAPHY_AVAILABLE:
            logging.error("Cannot use Google CT logs: cryptography module not installed")
        else:
            logging.info("=" * 60)
            logging.info("Querying Google CT Logs...")
            logging.info("=" * 60)
            
            for log_key, log_info in CT_LOG_SOURCES.items():
                if log_key.startswith('google_') and log_info.get('type') == 'ct_log':
                    if duration:
                        elapsed = (datetime.datetime.now() - start_time).total_seconds()
                        if elapsed > duration:
                            logging.info("Duration limit reached")
                            break
                    
                    ct_domains = query_ct_log_direct(log_info['url'], max_entries=500)
                    
                    for item in ct_domains:
                        all_domains.append({
                            'domain': item['domain'],
                            'source': f"Google-{log_key}"
                        })

    # Cloudflare CT Logs - SUPPLEMENTARY
    if 'cloudflare' in sources:
        if not CRYPTOGRAPHY_AVAILABLE:
            logging.error("Cannot use Cloudflare CT logs: cryptography module not installed")
        else:
            logging.info("=" * 60)
            logging.info("Querying Cloudflare CT Logs...")
            logging.info("=" * 60)
            
            for log_key, log_info in CT_LOG_SOURCES.items():
                if log_key.startswith('cloudflare_') and log_info.get('type') == 'ct_log':
                    if duration:
                        elapsed = (datetime.datetime.now() - start_time).total_seconds()
                        if elapsed > duration:
                            logging.info("Duration limit reached")
                            break
                    
                    ct_domains = query_ct_log_direct(log_info['url'], max_entries=500)
                    
                    for item in ct_domains:
                        all_domains.append({
                            'domain': item['domain'],
                            'source': f"Cloudflare-{log_key}"
                        })

    # Process all collected domains
    logging.info("=" * 60)
    logging.info(f"Processing {len(all_domains)} total domains...")
    logging.info("=" * 60)

    for item in all_domains:
        if duration:
            elapsed = (datetime.datetime.now() - start_time).total_seconds()
            if elapsed > duration:
                logging.info(f"Duration limit reached. Processed {len(processed_domains)} domains")
                break

        domain = item.get('domain', '').strip()
        source = item.get('source', 'unknown')

        if not domain or domain.startswith('*') or domain in processed_domains:
            continue

        processed_domains.add(domain)

        # STEP 1: Skip infrastructure/internal domains
        if is_infrastructure_domain(domain):
            logging.debug(f"[SKIP] Infrastructure: {domain}")
            continue

        # STEP 2: Require brand keywords (PRIMARY FILTER)
        has_brand, brand_keywords = contains_courier_keyword(domain)

        if not has_brand:
            logging.debug(f"[SKIP] No brand keywords: {domain}")
            continue

        # STEP 3: Check if on monitored platforms/TLDs
        matches_suffix = any(domain.endswith(suffix) for suffix in TARGET_SUFFIXES)

        if not matches_suffix:
            logging.debug(f"[SKIP] Not on suspicious platform: {domain}")
            continue

        # STEP 4: Calculate score
        score = calculate_score(domain)

        if score >= SCORE_THRESHOLD:
            findings_count += 1

            logging.warning(
                f"🚨 PHISHING DETECTED: {domain} | "
                f"Score: {score}/100 | "
                f"Keywords: {', '.join(brand_keywords)} | "
                f"Source: {source}"
            )

            add_to_feed(domain, score, source)

        else:
            logging.info(
                f"[LOW SCORE] {domain} (score: {score}) - "
                f"Keywords: {', '.join(brand_keywords)}"
            )

    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    save_run_stats(len(processed_domains), findings_count, elapsed)
    
    logging.info("=" * 60)
    logging.info("Scan complete!")
    logging.info(f"Domains processed: {len(processed_domains)}")
    logging.info(f"Phishing domains found: {findings_count}")
    logging.info(f"Elapsed time: {elapsed:.1f}s")
    logging.info("=" * 60)


# ==================== MAIN ====================


def main():
    global START_TIME, MAX_DURATION

    import argparse
    parser = argparse.ArgumentParser(description='Phishing Domain Detector - Courier & Government Edition')
    parser.add_argument('--duration', type=int, help='Run for N seconds and then exit', default=None)
    parser.add_argument('--sources', nargs='+', 
                       choices=['urlscan', 'google', 'cloudflare'], 
                       default=['urlscan'],
                       help='Sources to use (default: urlscan only)')
    args = parser.parse_args()

    MAX_DURATION = args.duration
    START_TIME = datetime.datetime.now()

    logging.info("=" * 60)
    logging.info("Phishing Domain Detector - Courier & Government Edition")
    logging.info("=" * 60)
    logging.info(f"Sources: {', '.join(args.sources)}")
    logging.info(f"Output: {OUTPUT_FILE}")
    logging.info(f"Targets: Bulgarian couriers + MVR e-services (e-uslugi.mvr.bg)")
    
    if MAX_DURATION:
        logging.info(f"Max duration: {MAX_DURATION} seconds")
    
    logging.info("=" * 60)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    if not os.path.exists(OUTPUT_FILE):
        save_feed([])

    scan_domains(duration=MAX_DURATION, sources=args.sources)


if __name__ == "__main__":
    main()
