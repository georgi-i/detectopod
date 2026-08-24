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
- **Smart Scoring**: ML-enhanced scoring system (0-100) based on domain patterns
- **LLM Analysis**: AI-powered review using Gemini 3.5 Flash to reduce false positives
- **Public Threat Feed**: JSON feed of detected domains updated in real-time
- **Zero Infrastructure**: Fully serverless using GitHub Actions

## 📊 Current Stats

<!-- STATS_START -->
```
Total Domains Detected: 304
Last Scan: 2026-08-24 13:03:21 UTC
Domains Processed: 6,817
Detection Rate: 2.8%
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
                           │ (Claude S. 4.5)  │
                           └──────────────────┘
                                    │
                                    ▼
                           ┌───────────────────┐
                           │  Threat Feed      │
                           │ phishing_feed.json│
                           └───────────────────┘
```

## 🔧 Installation

### Prerequisites
- Python 3.10+
- URLScan.io API key (free tier available)
- OpenRouter API key (for LLM analysis, optional)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/detectopod.git
   cd detectopod
   ```

2. **Install dependencies**
   ```bash
   pip install -r detection/requirements.txt
   pip install cryptography  # For CT log support
   ```

3. **Set environment variables**
   ```bash
   export URLSCAN_API_KEY="your_urlscan_api_key"
   export OPENROUTER_API_KEY="your_openrouter_key"  # Optional
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
# Analyze last 24 hours of detections
python detection/llm_analyzer.py --days 1 --max-analyze 50

# Analyze with custom threshold
python detection/llm_analyzer.py --min-score 80 --max-analyze 100
```

### Accessing the Feed

The threat feed is automatically updated at `feed/phishing_feed.json`:

```json
[
  {
    "domain": "speedy.bg-pk.cfd",
    "score": 100,
    "detected_at": "2026-01-29T18:11:25.161773",
    "source": "urlscan.io-.cfd"
  },
  {
    "domain": "mvrbg.sbs",
    "score": 100,
    "detected_at": "2026-05-08T12:00:00.000000",
    "source": "urlscan.io-.sbs"
  }
]
```

## 🤖 GitHub Actions Workflows

### Scheduled Detection (`scheduled-detection.yml`)
- **Frequency**: Every Monday at noon UTC
- **Sources**: URLScan.io + Google CT + Cloudflare CT
- **Timeout**: 20 minutes
- **Auto-commit**: Updates feed automatically

### LLM Analysis (`llm_analysis.yml`)
- **Frequency**: Every Monday at 2 PM UTC (2h after detection)
- **Model**: Claude Sonnet 4.5 via OpenRouter
- **Purpose**: Validate detections and remove false positives
- **Max domains**: 1000 per run (BYOK, no artificial cap)

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
`mvr`, `mvrbg`, `e-uslugi`, `euslugi`

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

Recent scan statistics:
- **Domains scanned**: ~1,800 per run
- **Processing time**: ~18 seconds
- **Detection rate**: ~5%
- **False positive rate**: <10% (with LLM validation)

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
- [OpenRouter](https://openrouter.ai/) - LLM analysis API
- Bulgarian cybersecurity community

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/georgi-i/detectopod/issues)
- **Discussions**: [GitHub Discussions](https://github.com/georgi-i/detectopod/discussions)

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. The threat feed is provided as-is without warranty. Always verify domains before taking action.

---

**Status**: 🟢 Active | **Last Updated**: 2026-05-08 | **Version**: 1.1
