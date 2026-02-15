# Detectopod 🔍

**Automated phishing domain detection targeting Bulgarian courier services**

Detectopod is an automated threat intelligence system that monitors the web for phishing domains impersonating Bulgarian courier and logistics companies like Econt, Speedy, and BulgariaPost. The system runs continuously via GitHub Actions and maintains a public threat feed.

## 🎯 What It Does

Detectopod identifies phishing domains that:
- Impersonate Bulgarian courier brands (Econt, Speedy, BulgariaPost, etc.)
- Use suspicious TLDs (`.cfd`, `.tk`, `.ml`, `.ga`, etc.)
- Deploy on free hosting platforms (Cloudflare Pages, Firebase, Heroku, Netlify, Vercel)
- Exhibit classic phishing patterns (e.g., `speedy.bg-pk.cfd`, `econt-paydelivery.cfd`)

## 🚀 Features

- **Multi-Source Detection**: Queries URLScan.io, Google CT logs, and Cloudflare CT logs
- **Automated Scanning**: Runs hourly via GitHub Actions
- **Smart Scoring**: ML-enhanced scoring system (0-100) based on domain patterns
- **LLM Analysis**: Daily AI-powered review using Llama 3.3 70B to reduce false positives
- **Public Threat Feed**: JSON feed of detected domains updated in real-time
- **Zero Infrastructure**: Fully serverless using GitHub Actions

## 📊 Current Stats

```
Total Domains Detected: 96
Last Scan: 2026-01-29 18:59:28 UTC
Domains Processed: 1,817
Detection Rate: 5.3%
```

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
                           │ (Llama 3.3 70B)  │
                           | (Claude S. 4.5)  |
                           └──────────────────┘
                                    │
                                    ▼
                           ┌────────────────── ┐
                           │  Threat Feed      │
                           │ phishing_feed.json│
                           └────────────────── ┘
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
  }
]
```

## 🤖 GitHub Actions Workflows

### Scheduled Detection (`scheduled-detection.yml`)
- **Frequency**: Every hour
- **Sources**: URLScan.io + Google CT + Cloudflare CT
- **Timeout**: 20 minutes
- **Auto-commit**: Updates feed automatically

### LLM Analysis (`llm_analysis.yml`)
- **Frequency**: Daily at 2 AM UTC
- **Model**: Llama 3.3 70B via OpenRouter
- **Purpose**: Validate detections and remove false positives
- **Max domains**: 50 per run

## 🎯 Detection Logic

### Scoring System (0-100)

| Factor | Weight | Example |
|--------|--------|---------|
| Bulgarian courier brand presence | +35 | `speedy`, `econt`, `bgpost` |
| Geographic indicator | +15 | `.bg`, `bulgaria`, `bg-` |
| Suspicious TLD | +30 | `.cfd`, `.tk`, `.ml` |
| Free hosting platform | +25 | `.pages.dev`, `.web.app` |
| Brand + Geo + Suspicious TLD | +45 | `speedy.bg-pk.cfd` |
| Brand + Free hosting | +40 | `speedy-37a.pages.dev` |
| Multiple hyphens (with brand) | +8 each | `speedy-trans-bg` |
| Random alphanumeric patterns | +12 | `g63829`, `37a` |
| Phishing keywords | +15 | `payment`, `verify`, `secure` |

**Threshold**: Domains scoring ≥80 are added to the feed.

### Monitored Platforms

**Suspicious TLDs:**
`.cfd`, `.tk`, `.ml`, `.ga`, `.gq`, `.cf`, `.top`, `.xyz`, `.club`, `.online`, `.site`, `.space`, `.click`, `.link`, `.live`, `.icu`

**Free Hosting:**
Firebase (`.web.app`, `.firebaseapp.com`), Cloudflare Pages (`.pages.dev`), Heroku (`.herokuapp.com`), Netlify (`.netlify.app`), Vercel (`.vercel.app`), Render, GitHub Pages, and more.

## 🎛️ Configuration

### Target Keywords

**Primary (Bulgarian couriers):**
`econt`, `speedy`, `bulgariapost`, `bgpost`, `samedaybg`, `boxnowbg`, `cityexpressbg`, `expressonebg`, `dhl`

**Secondary (generic logistics):**
`tracking`, `delivery`, `shipment`, `parcel`, `payment`, `tax`, `fee`, `customer-center`

### Thresholds

```python
SCORE_THRESHOLD = 80  # Minimum score for feed inclusion
```

## 📈 Performance

Recent scan statistics:
- **Domains scanned**: ~1,800 per hour
- **Processing time**: ~18 seconds
- **Detection rate**: ~5% (96 phishing domains found)
- **False positive rate**: <10% (with LLM validation)

## 🔐 Security Considerations

- All API keys stored as GitHub Secrets
- No sensitive data in repository
- Read-only feeds (public access)
- Automated threat intelligence sharing

## 🤝 Contributing

Contributions welcome! Areas for improvement:

1. **New detection patterns**: Suggest additional phishing indicators
2. **Expanded coverage**: Add more courier brands or regions
3. **Performance optimization**: Improve scanning efficiency
4. **False positive reduction**: Enhance scoring algorithms

### Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/detectopod.git

# Create feature branch
git checkout -b feature/new-detection-pattern

# Make changes and test
python detection/detectopod.py --sources urlscan

# Submit PR
```

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

**Status**: 🟢 Active | **Last Updated**: 2026-01-29 | **Version**: 1.0
