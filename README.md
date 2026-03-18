# 🛡️ DGR Site — Dangerous Site Checker

A Python-based tool that checks URLs against the VirusTotal threat intelligence platform to identify sites flagged as dangerous or suspicious by security vendors. When flags are found, the system will facilitate automated false-positive appeal submissions to the relevant vendors.

---

## 🎯 Goals

| | Goal | Description |
|---|---|---|
| 🔍 | **Detect** | Scan URLs via VirusTotal API and identify which vendors have flagged them |
| 📋 | **Report** | Show which vendors flagged each URL with their verdict labels |
| ✉️ | **Appeal** | Auto-submit false positive appeals to each flagging vendor |

---

## 📁 Project Structure

```
DGR-Site/
├── checker.py          # Main script — reads URLs, calls VT API, prints results
├── urls.json           # Input file — list of URLs to check (excluded from git)
├── .env                # API key and config variables (excluded from git)
├── .env.example        # Safe template showing required variables
├── .gitignore          # Excludes .env, urls.json, ds/ from git
└── ds/                 # Python virtual environment (excluded from git)
```

---

## ⚙️ Setup

**1. Clone the repo and navigate to the project folder**
```bash
git clone https://github.com/your-repo/DGR-Site.git](https://github.com/MijiChongHUH/Automated-Dangerous-Site-Appealing-System.git
cd DGR-Site
```

**2. Create and activate virtual environment**
```bash
python -m venv ds --without-pip
ds\Scripts\Activate.ps1        # Windows PowerShell
# source ds/bin/activate       # Mac / Linux
python -m ensurepip --upgrade
```

**3. Install dependencies**
```bash
pip install requests python-dotenv
```

**4. Configure your `.env` file**
```bash
cp .env.example .env
# Then edit .env and add your VirusTotal API key
```

**5. Add URLs to `urls.json`**
```json
{
  "urls": [
    "example.com",
    "suspicious-site.com"
  ]
}
```

---

## 🚀 Usage

```bash
# Check all URLs in urls.json
python checker.py

# Check a single URL
python checker.py --url example.com
```

### Example Output
```
════════════════════════════════════════════════════════════
  VirusTotal URL Checker
  URLs to check : 3
  Rate limit    : 15s between API calls
════════════════════════════════════════════════════════════

[1/3] Checking: https://example.com
  [API] Fetching VT report...
  [OK] VT report is fresh (within 24h), using it.
  Status   : 🟢 CLEAN
  Malicious: 0  Suspicious: 0  Harmless: 72  Undetected: 14  (of 86 vendors)
  Flagged by: none

[2/3] Checking: https://suspicious-site.com
  [API] Fetching VT report...
  [STALE] VT report is older than 24h — submitting for rescan...
  Status   : 🔴 DANGEROUS
  Malicious: 5  Suspicious: 2  Harmless: 60  Undetected: 10  (of 77 vendors)
  Flagged by (5 vendors):
    • Vendor A: malware
    • Vendor B: phishing

════════════════════════════════════════════════════════════
  SUMMARY  (3 URLs checked)
════════════════════════════════════════════════════════════
  🔴 Dangerous  : 1
  🟡 Suspicious : 0
  🟢 Clean      : 2
  ⚠️  Errors     : 0
```

---

## 🔄 How the Checker Works

Each URL goes through this decision flow:

```
Step 1 — Fetch VT Report
    GET /urls/{id}
    Retrieves VirusTotal's stored scan report (1 API call)
         │
         ▼
Step 2 — Check Freshness
    Is VT's last analysis within 24 hours?
    ├── YES → Use result immediately ✅
    └── NO  → Proceed to Step 3
         │
         ▼
Step 3 — Submit Fresh Scan
    POST /urls  →  submit URL for new scan
    GET  /analyses/{id}  →  poll until completed
    (~2 API calls)
         │
         ▼
Step 4 — Display Results
    🔴 DANGEROUS  /  🟡 SUSPICIOUS  /  🟢 CLEAN
    + list of flagging vendors and their verdicts
```

---

## ⏱️ Rate Limiting

Free VirusTotal tier limits:

| Limit | Value | How it's handled |
|-------|-------|-----------------|
| Per minute | 4 requests | 15s sleep after every API call |
| Per day | 500 requests | User manages number of URLs per run |
| Cache window | 24 hours | VT reports fresher than 24h are reused without rescanning |

---

## 🔒 Security

- API key stored in `.env` — never hardcoded in source files
- `urls.json` excluded from git — URL list stays private
- Virtual environment `ds/` excluded from git
- `.env.example` committed as a safe reference template

---

## 🗺️ Implementation Roadmap

| Phase | Name | Description | Status |
|-------|------|-------------|--------|
| **1** | URL Checker (Python Script) | Read URLs from `urls.json`, call VirusTotal API, display results in terminal with rate limiting and 24h freshness check | ✅ Done |
| **2** | Frontend Web Interface | Move `checker.py` to a script server with a web frontend so users can submit URLs through a browser UI instead of terminal | 📋 Next |
| **3** | Vendor Map & Appeal Router | Build a lookup table mapping each security vendor to their false positive web form URL or appeal email address | 🔜 Planned |
| **4** | Automated Form Submission | Use Playwright/Selenium to auto-fill false positive forms. Pause for user to solve reCAPTCHA, then auto-submit | 🔜 Planned |
| **5** | Automated Email Appeals | Generate and send appeal emails to vendors that require email-based false positive reports | 🔜 Planned |
| **6** | Appeal Status Tracking | Track which vendors have been contacted, when, and what response was received per URL | 🔜 Planned |

---

## 🔭 Phase 2 — Frontend Web Interface

Currently the checker runs in the terminal. Phase 2 wraps it with a web frontend.

| | Current (Phase 1) | Phase 2 (Web Frontend) |
|---|---|---|
| **How to run** | `python checker.py` in terminal | Open browser → enter URLs → click Check |
| **Input** | Edit `urls.json` manually | Submit URLs via web form |
| **Output** | Printed to terminal | Rendered in a web table |
| **Access** | Requires Python + VS Code | Accessible by anyone on the network |
| **Backend** | Standalone script | Flask / FastAPI server |

---

## 📬 Phase 3–5 — False Positive Appeal System

### Phase 3 — Vendor Map
Build a JSON lookup table mapping each VirusTotal vendor name to their appeal method:

```json
{
  "Google Safe Browsing": {
    "method": "form",
    "url": "https://safebrowsing.google.com/safebrowsing/report_error"
  },
  "Vendor B": {
    "method": "email",
    "address": "appeal@vendor.com"
  }
}
```

> ⚠️ Vendor details (form URLs / email addresses) are still being researched.

### Phase 4 — Automated Form Submission
Using **Playwright** (browser automation):
1. Open vendor's appeal form in a headless browser
2. Auto-fill fields: URL, reason (false positive), contact details
3. Detect reCAPTCHA → pause and show browser window to user
4. User solves reCAPTCHA manually, script resumes and clicks Submit
5. Record submission timestamp and confirmation per vendor per URL

### Phase 5 — Email Appeals
For vendors that require email-based appeals:
1. Generate a formatted false positive appeal email
2. Send via SMTP (configured in `.env`) or pre-fill user's email client
3. Log which vendors were emailed and when

---

## 🛠️ Technology Stack

| Phase | Technology | Purpose |
|-------|-----------|---------|
| 1 (current) | `Python 3.12`, `requests`, `python-dotenv` | CLI checker, API calls, environment config |
| 2 | `Flask` or `FastAPI`, HTML/JS | Web server and browser frontend |
| 3–4 | `Playwright`, JSON vendor map | Browser automation, vendor routing |
| 5–6 | `smtplib`, SQLite / JSON | Email sending, appeal history tracking |

---

## 📌 Immediate Next Steps

- [ ] Test `checker.py` with real URLs and verify terminal output
- [ ] Regenerate VirusTotal API key *(previous key was exposed in git history)*
- [ ] Run `git rm --cached` to remove previously committed `.env` from git tracking
- [ ] Research each flagging vendor — note whether they use a web form or email for appeals
- [ ] Prepare the vendor map JSON file with form URLs / email addresses
- [ ] Begin Phase 2 — set up Flask/FastAPI server and basic web frontend

---

## 📄 License

Internal use only — BS Group
