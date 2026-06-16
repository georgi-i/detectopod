#!/usr/bin/env python3
"""
Updates the <!-- STATS_START --> ... <!-- STATS_END --> block in README.md
with live numbers pulled from feed/phishing_feed.json and feed/run_stats.json.

Called by scheduled-detection.yml after every scan run.
"""

import json
import os
import re

FEED_FILE  = "feed/phishing_feed.json"
STATS_FILE = "feed/run_stats.json"
README     = "README.md"

# --- gather numbers ---
total = 0
if os.path.exists(FEED_FILE):
    with open(FEED_FILE) as f:
        total = len(json.load(f))

last_scan = "N/A"
processed = 0
rate_str  = "N/A"

if os.path.exists(STATS_FILE):
    with open(STATS_FILE) as f:
        s = json.load(f)
    last_scan = s.get("last_run", "N/A")
    processed = s.get("domains_scanned", 0)
    found     = s.get("phishing_found", 0)
    rate_str  = f"{found / processed * 100:.1f}%" if processed else "N/A"

# --- build replacement block ---
# Triple backticks stored in a variable to avoid any escaping issues.
fences = "```"
block = (
    "<!-- STATS_START -->\n"
    f"{fences}\n"
    f"Total Domains Detected: {total:,}\n"
    f"Last Scan: {last_scan}\n"
    f"Domains Processed: {processed:,}\n"
    f"Detection Rate: {rate_str}\n"
    f"{fences}\n"
    "<!-- STATS_END -->"
)

# --- rewrite README ---
if not os.path.exists(README):
    print(f"❌ {README} not found — skipping")
    raise SystemExit(1)

with open(README) as f:
    content = f.read()

updated, n = re.subn(
    r"<!-- STATS_START -->.*?<!-- STATS_END -->",
    block,
    content,
    flags=re.DOTALL,
)

if n == 0:
    print("⚠️  STATS markers not found in README.md — nothing updated")
    raise SystemExit(0)

with open(README, "w") as f:
    f.write(updated)

print(f"✓ README stats updated — {total:,} domains, last scan: {last_scan}")
