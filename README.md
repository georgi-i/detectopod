# Detectopod 🔍

**Automated phishing domain detection targeting Bulgarian courier services, government e-portals, and toll payment services**

Detectopod is an automated threat intelligence system that monitors the web for phishing domains impersonating Bulgarian courier and logistics companies (Econt, Speedy, BulgariaPost), the Bulgarian Ministry of Interior e-services portal (`e-uslugi.mvr.bg`), **and** the TollPass / Vinetki toll payment services (`tollpass.bg`, `vinetki.bg`). The system runs continuously via GitHub Actions and maintains a public threat feed.

## 🎯 What It Does

Detectopod identifies phishing domains that:
- Impersonate Bulgarian courier brands (Econt, Speedy, BulgariaPost, etc.)
- Impersonate Bulgarian government e-services — specifically the MVR portal (`e-uslugi.mvr.bg`)
- Impersonate Bulgarian toll/vignette payment services — TollPass (`tollpass.bg`) and Vinetki (`vinetki.bg`)
- Use suspicious TLDs (`.cfd`, `.tk`, `.sbs`, `.cam`, `.shop`, `.autos`, `.life`, `.one`, `.cc`, etc.)
- Deploy on free hosting platforms (Cloudflare Pages, Firebase, Heroku, Netlify, Vercel)
- Exhibit classic phishing patterns (e.g., `speedy.bg-pk.cfd`, `mvrbg.sbs`, `e-uslugicye.top`, `tollpassapp.top`)

## 🚀 Features

- **Multi-Source Detection**: Queries URLScan.io, Google CT logs, and Cloudflare CT logs
- **Automated Scanning**: Runs weekly via GitHub Actions
- **Rule-based Scoring**: Transparent scoring system (0-100) based on brand, TLD, hosting and domain patterns
- **LLM Analysis**: AI-powered review using Gemini 3.5 Flash (structured JSON output) to reduce false positives
- **False-Positive Memory**: Domains you reject are remembered in `feed/false_positives.json` and never re-added
- **Public Threat Feed**: JSON feed of detected domains updated in real-time
- **Zero Infrastructure**: Fully serverless using GitHub Actions

## 📊 Current Stats

<!-- STATS_START -->
```
Total Domains Detected: 306
Last Scan: 2026-09-28 19:33:30 UTC
Domains Processed: 6,980
Detection Rate: 2.7%
```
<!-- STATS_END -->

## 🏗️ Architecture

```
┌─────────────────┐
│  URLScan.io API │──┐
└─────────────────┘  │
                     │
┌─────────────────┐  │     ┌──────────────────┐
│ Google CT Logs  │──┼────▶│  detectopod.py   │
└─────────────────┘  │     │  (Main Scanner)  │
                     │     └──────────────────┘
┌─────────────────┐  │              │
│ Cloudflare CT   │──┘              │
└─────────────────┘                 │
                                    ▼
                           ┌──────────────────┐
                           │ Scoring Engine   │
                           │ - Keyword match  │
                           │ - Pattern detect │
                           │ - TLD analysis   │
                           └──────────────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │ LLM Analyzer     │
                           │ (Gemini 3.5)     │
                           └──────────────────┘
                                    │
                                    ▼
                           ┌───────────────────┐   ┌────────────────────┐
                           │  Threat Feed      │◀──│ false_positives.json│
                           │ phishing_feed.json│   │ (never re-added)   │
                           └───────────────────┘   └────────────────────┘
```

## 🔧 Installation

### Prerequisites
- Python 3.10+
- URLScan.io API key (free tier available)
- Google AI Studio API key (`GEMINI_API_KEY`, for LLM analysis, optional)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/georgi-i/detectopod.git
   cd detectopod
   ```

2. **Install dependencies**
   ```bash
   pip install -r detection/requirements.txt  # requests + cryptography (CT logs)
   ```

3. **Set environment variables**
   ```bash
   export URLSCAN_API_KEY="your_urlscan_api_key"
   export GEMINI_API_KEY="your_gemini_key"  # Optional, for LLM analysis
   ```

4. **Run the scanner**
   ```bash
   # Quick scan (URLScan.io only)
   python detection/detectopod.py --sources urlscan
   
   # Full scan (all sources)
   python detection/detectopod.py --sources urlscan google cloudflare
   
   # Time-limited scan
   python detection/detectopod.py --duration 300  # 5 minutes
   ```

## 📋 Usage

### Manual Scanning

```bash
# Scan using URLScan.io only (recommended for quick tests)
python detection/detectopod.py --sources urlscan

# Comprehensive scan using all sources
python detection/detectopod.py --sources urlscan google cloudflare

# Run for specific duration
python detection/detectopod.py --duration 600 --sources urlscan
```

### LLM Analysis

```bash
# Analyze detections from the last 24 hours
python detection/llm_analyzer.py --days 1 --max-analyze 50

# Analyze with custom threshold
python detection/llm_analyzer.py --min-score 80 --max-analyze 100
```

Entries whose analysis was truncated (`UNKNOWN`) are re-queued automatically, and domains
listed in `feed/false_positives.json` are skipped.

### Accessing the Feed

The threat feed is automatically updated at `feed/phishing_feed.json`:

```json
[
  {
    "domain": "speedy.bg-pk.cfd",
    "score": 100,
    "detected_at": "2026-01-29T18:11:25.161773",
    "source": "urlscan.io-.cfd",
    "keywords": ["speedy"],
    "llm_analysis": {
      "model": "gemini-3.5-flash",
      "threat_level": "HIGH",
      "confidence": 98,
      "decision": "BLOCK"
    }
  },
  {
    "domain": "mvrbg.sbs",
    "score": 100,
    "detected_at": "2026-05-08T12:00:00.000000",
    "source": "urlscan.io-.sbs"
  }
]
```

Domains are stored without the `www.` prefix. `keywords` and `llm_analysis` are added by the
detector and the analyzer respectively (older entries may lack them).

Other files in `feed/`: `false_positives.json` (suppression list), `run_stats.json` and
`llm_analysis_stats.json` (last-run statistics).

## 🤖 GitHub Actions Workflows

### Scheduled Detection (`scheduled-detection.yml`)
- **Frequency**: Every Monday at noon UTC (or manually)
- **Sources**: URLScan.io + Google CT + Cloudflare CT
- **Timeout**: 20 minutes
- **Auto-commit**: Updates feed automatically
- All workflows that write to `feed/` share the `feed-writer` concurrency group, so they never run at the same time

### LLM Analysis (`llm_analysis.yml`)
- **Trigger**: Right after a successful Scheduled Detection run (or manually)
- **Model**: Gemini 3.5 Flash (fallback: 2.5 Flash-Lite) via Google AI Studio, JSON output
- **Purpose**: Validate detections and remove false positives
- **Max domains**: 100 per run (`max_analyze` input when run manually); entries with a truncated (`UNKNOWN`) analysis are re-queued automatically
- **Branch runs**: when started from a branch other than `main` it never pushes; the resulting feed is uploaded as an artifact instead

### Mark False Positive (`mark_false_positive.yml`)
Manual workflow: enter a domain, it is added to `feed/false_positives.json` and removed from the feed.

## 🚫 False Positives

`feed/false_positives.json` is the single source of truth for "never show this again".
The detector and the LLM analyzer both read it, so a listed domain is never re-added.

```json
{ "domain": "tollpass.xyz", "subdomains": true }
```

- default: exact match (`www.` is ignored)
- `"subdomains": true`: the domain **and** all its subdomains (`test.`, `dev.`, `www.` ...)
- add one from the CLI: `python detection/fp.py tollpass.xyz --subdomains`
- or via the **Mark False Positive** workflow in the Actions tab
- hosts starting with `test.`, `dev.`, `staging.`, `qa.`, `uat.`, `sandbox.` are skipped automatically

Offline tests: `python -m unittest discover -s tests`

## 🎯 Detection Logic

### Scoring System (0-100)

#### Courier Brands (Econt, Speedy, BulgariaPost…)

| Factor | Weight | Example |
|--------|--------|---------|
| Bulgarian courier brand present | +35 | `speedy`, `econt`, `bgpost` |
| Geographic indicator | +15 | `.bg`, `bulgaria`, `bg-` |
| Suspicious TLD | +30 | `.cfd`, `.tk`, `.sbs` |
| Free hosting platform | +25 | `.pages.dev`, `.web.app` |
| Brand + geo + suspicious TLD | +45 | `speedy.bg-pk.cfd` |
| Brand + suspicious TLD | +25 | `econt-paydelivery.cfd` |
| Brand + free hosting | +40 | `speedy-37a.pages.dev` |
| Brand + geo + free hosting | +30 | `econt-bg-xxx.web.app` |
| Multiple hyphens (with brand) | +8 each | `speedy-trans-bg` |
| Random alphanumeric patterns | +12 | `g63829`, `37a` |
| Phishing keywords | +15 | `payment`, `verify`, `secure` |

#### Government Brands (MVR / e-uslugi.mvr.bg)

| Factor | Weight | Example |
|--------|--------|---------|
| MVR / mvrbg / e-uslugi present | +40 | `mvr`, `mvrbg`, `e-uslugi` |
| Geographic indicator | +15 | `bggov`, `govbg`, `bg-` |
| Suspicious TLD | +30 | `.sbs`, `.cam`, `.autos`, `.shop` |
| Brand + geo + suspicious TLD | +45 | `mvr.bggov.cam` |
| Brand + suspicious TLD | +25 | `mvrbg.sbs` |
| Brand + free hosting | +40 | `mvr-bg.pages.dev` |

#### Toll/Vignette Brands (TollPass / Vinetki)

| Factor | Weight | Example |
|--------|--------|---------|
| tollpass / vinetki present | +40 | `tollpass`, `vinetki` |
| Geographic indicator | +15 | `.bg`, `bulgaria`, `bg-` |
| Suspicious TLD | +30 | `.cam`, `.top`, `.cc` |
| Brand + geo + suspicious TLD | +45 | `tollpass.klgf.cam` |
| Brand + suspicious TLD | +25 | `tollpassapp.top` |
| Brand + free hosting | +40 | `tollpass-xxx.pages.dev` |

**Threshold**: Domains scoring ≥80 are added to the feed.

### Monitored Platforms

**Suspicious TLDs:**
`.cfd`, `.tk`, `.ml`, `.ga`, `.gq`, `.cf`, `.top`, `.xyz`, `.club`, `.online`,
`.site`, `.space`, `.click`, `.link`, `.live`, `.icu`, `.sbs`, `.cam`, `.shop`,
`.one`, `.autos`, `.life`, `.qpon`, `.uno`, `.ink`, `.cyou`, `.cc`

**Free Hosting:**
Firebase (`.web.app`, `.firebaseapp.com`), Cloudflare Pages (`.pages.dev`),
Heroku (`.herokuapp.com`), Netlify (`.netlify.app`), Vercel (`.vercel.app`),
Render, GitHub Pages, and more.

## 🎛️ Configuration

### Target Keywords

**Courier brands:**
`econt`, `speedy`, `bulgariapost`, `bgpost`, `samedaybg`, `boxnowbg`,
`cityexpressbg`, `expressonebg`, `dhl`

**Government brands (MVR):**
`mvr`, `mvrbg`, `mvr-bg`, `mvr-gov`, `e-uslugi`, `euslugi`

**Toll/vignette brands (TollPass / Vinetki):**
`tollpass`, `vinetki`

**Secondary (generic logistics):**
`tracking`, `delivery`, `shipment`, `parcel`, `payment`, `tax`, `fee`,
`customer-center`

### Geographic Indicators
`.bg`, `bulgaria`, `bg-`, `-bg`, `bggov`, `govbg`, `gov-bg`, `bg-gov`

### Thresholds

```python
SCORE_THRESHOLD = 80  # Minimum score for feed inclusion
```

## 📈 Performance

See the live numbers in [Current Stats](#-current-stats) above (updated after every scan from
`feed/run_stats.json`). A full URLScan run processes several thousand domains in a few minutes;
LLM analysis takes a few seconds per domain and is rate limited by Google AI Studio.

Note: the rule-based score saturates at 100 for most matches, so the LLM review is what separates
real phishing from look-alikes.

## 🔐 Security Considerations

- All API keys stored as GitHub Secrets
- No sensitive data in repository
- Read-only feeds (public access)
- Automated threat intelligence sharing

## 🤝 Contributing

Contributions welcome! Areas for improvement:

1. **New detection patterns**: Suggest additional phishing indicators
2. **Expanded coverage**: Add more brands or government services
3. **Performance optimization**: Improve scanning efficiency
4. **False positive reduction**: Enhance scoring algorithms

## 📜 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- [URLScan.io](https://urlscan.io/) - Primary data source
- [Certificate Transparency](https://certificate.transparency.dev/) - CT log infrastructure
- [Google AI Studio (Gemini)](https://aistudio.google.com/) - LLM analysis API
- Bulgarian cybersecurity community

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/georgi-i/detectopod/issues)
- **Discussions**: [GitHub Discussions](https://github.com/georgi-i/detectopod/discussions)

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. The threat feed is provided as-is without warranty. Always verify domains before taking action.

---

**Status**: 🟢 Active | **Version**: 1.2
