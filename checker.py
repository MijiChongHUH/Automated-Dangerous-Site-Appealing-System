"""
VirusTotal URL Checker + False Positive Appeal
==============================================
Reads URLs from urls.json, checks each against VirusTotal API,
prints results, then immediately triggers false positive appeal
submissions for any vendors that flagged the URL.

Flow per URL:
  1. Check URL against VirusTotal
  2. Display results
  3. For each flagging vendor that has a vendor module → open appeal form
  4. Move on to the next URL

Rate limiting (free tier):
  - 4 requests/minute → 15s gap between each API call
  - 500 requests/day

Usage:
  python checker.py                  # Check all URLs in urls.json
  python checker.py --url <url>      # Check a single URL
"""

import json
import time
import hashlib
import base64
import argparse
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library not found. Run: pip install requests")
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("[ERROR] 'python-dotenv' not found. Run: pip install python-dotenv")
    sys.exit(1)

# ─── Vendor appeal registry ───────────────────────────────────────────────────
# Maps VirusTotal vendor name (lowercase) → appeal module
# Add new vendors here as vendors/<name>.py is created

VENDOR_MODULES = {}

def _load_vendor_modules():
    """Dynamically load all available vendor modules from vendors/ folder."""
    vendors_dir = Path("vendors")
    if not vendors_dir.exists():
        return
    for f in vendors_dir.glob("*.py"):
        if f.name == "__init__.py":
            continue
        module_name = f.stem  # e.g. "alphamountain"
        try:
            import importlib.util
            spec   = importlib.util.spec_from_file_location(module_name, f)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            # Register under the vendor name defined in the module
            vt_name = getattr(module, "VENDOR_NAME", module_name)
            VENDOR_MODULES[vt_name.lower()] = module
            print(f"  [VENDOR] Loaded appeal module: {vt_name}")
        except Exception as e:
            print(f"  [VENDOR] Failed to load {f.name}: {e}")

# ─── Load .env ────────────────────────────────────────────────────────────────

load_dotenv()

def _require_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        print(f"[ERROR] Missing required env variable: {key}")
        print(f"        Add it to your .env file. See .env.example for reference.")
        sys.exit(1)
    return val

# ─── Configuration ────────────────────────────────────────────────────────────

API_KEY          = _require_env("VT_API_KEY")
BASE_URL         = "https://www.virustotal.com/api/v3"
URLS_FILE        = os.getenv("URLS_FILE", "urls.json")
CACHE_MAX_AGE    = timedelta(hours=int(os.getenv("CACHE_MAX_AGE_HOURS", "24")))
RATE_LIMIT_SLEEP = 15  # seconds between API calls (4 per min = 15s gap)

HEADERS = {
    "x-apikey": API_KEY,
    "Accept":   "application/json",
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_id(url: str) -> str:
    """
    VirusTotal URL ID = URL-safe base64(sha256(url)) with no padding.
    IMPORTANT: VT computes the hash on the normalised URL it stores internally.
    For bare domains (no scheme) VT may normalise differently, so we also
    try the https:// prefixed version as a fallback in fetch_report().
    """
    digest = hashlib.sha256(url.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def url_to_id_variants(url: str) -> list:
    """
    Return all ID variants to try for a given input:
      - as-is
      - with https:// prefix (if no scheme present)
      - with http://  prefix (if no scheme present)
    This handles bare domains like 'bk-8good.biz' gracefully.
    """
    variants = [url]
    if not url.startswith("http://") and not url.startswith("https://"):
        variants.append("https://" + url)
        variants.append("http://"  + url)
    return [url_to_id(v) for v in variants]


def wait():
    """Sleep between API calls to respect the 4 req/min free tier limit."""
    print(f"  [RATE] Waiting {RATE_LIMIT_SLEEP}s before next API call...")
    time.sleep(RATE_LIMIT_SLEEP)


def is_within_24h(timestamp_str: str) -> bool:
    """Return True if the ISO timestamp is within the last 24 hours."""
    if not timestamp_str:
        return False
    try:
        ts = datetime.fromisoformat(timestamp_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts) < CACHE_MAX_AGE
    except Exception:
        return False


def parse_analysis(attributes: dict) -> dict:
    """Extract a clean summary from VT analysis attributes."""
    stats   = attributes.get("last_analysis_stats", {})
    vendors = attributes.get("last_analysis_results", {})

    flagged = {
        vendor: info.get("result") or info.get("category", "unknown")
        for vendor, info in vendors.items()
        if info.get("category") in ("malicious", "suspicious")
    }

    last_analysis_ts  = attributes.get("last_analysis_date")
    last_analysis_str = None
    if last_analysis_ts:
        last_analysis_str = datetime.fromtimestamp(
            last_analysis_ts, tz=timezone.utc
        ).isoformat()

    return {
        "malicious":        stats.get("malicious", 0),
        "suspicious":       stats.get("suspicious", 0),
        "harmless":         stats.get("harmless", 0),
        "undetected":       stats.get("undetected", 0),
        "total_vendors":    sum(stats.values()),
        "flagged_by":       flagged,
        "last_vt_analysis": last_analysis_str,
    }

# ─── API calls ────────────────────────────────────────────────────────────────

def fetch_report(url: str) -> dict | None:
    """
    GET /urls/{id} — fetch VT's stored report for a URL.
    Tries all ID variants (bare domain, https://, http://) so that
    entries like 'bk-8good.biz' are found even without a scheme.
    Returns parsed result dict if found, None if not found.
    """
    ids = url_to_id_variants(url)
    print(f"  [API] Fetching VT report...")

    for url_id in ids:
        resp = requests.get(f"{BASE_URL}/urls/{url_id}", headers=HEADERS, timeout=20)
        wait()

        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            return parse_analysis(attrs)

        if resp.status_code == 404:
            continue  # Try next variant

        if resp.status_code == 400:
            continue  # Invalid ID for this variant, try next

        print(f"  [WARN] Unexpected response {resp.status_code}: {resp.text[:200]}")

    return None  # Not found under any variant


def submit_url(url: str) -> str | None:
    """
    POST /urls — submit URL for a fresh scan.
    VT accepts bare domains, http://, or https:// — no normalisation needed.
    Returns the analysis ID, or None on failure.
    """
    print(f"  [API] Submitting URL for fresh scan...")
    resp = requests.post(
        f"{BASE_URL}/urls",
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        data={"url": url},
        timeout=20,
    )
    wait()

    if resp.status_code in (200, 201):
        return resp.json().get("data", {}).get("id")

    print(f"  [WARN] Submit failed {resp.status_code}: {resp.text[:200]}")
    return None


def poll_analysis(analysis_id: str) -> dict | None:
    """
    GET /analyses/{id} — poll until scan is completed (max 6 attempts).
    Returns parsed result dict, or None if timed out.
    """
    for attempt in range(1, 7):
        print(f"  [API] Polling result (attempt {attempt}/6)...")
        time.sleep(10)
        resp = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=20,
        )
        wait()

        if resp.status_code != 200:
            continue

        data   = resp.json().get("data", {})
        status = data.get("attributes", {}).get("status")

        if status == "completed":
            attrs       = data.get("attributes", {})
            results_raw = attrs.get("results", {})

            stats   = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
            flagged = {}

            for vendor, info in results_raw.items():
                cat = info.get("category", "undetected")
                if cat in stats:
                    stats[cat] += 1
                if cat in ("malicious", "suspicious"):
                    flagged[vendor] = info.get("result") or cat

            return {
                "last_vt_analysis": datetime.now(timezone.utc).isoformat(),
                "total_vendors":    sum(stats.values()),
                "flagged_by":       flagged,
                **stats,
            }

    print(f"  [WARN] Polling timed out after 6 attempts.")
    return None

# ─── Core checker ─────────────────────────────────────────────────────────────

def check_url(url: str) -> dict:
    """
    Check a single URL against VirusTotal:
    1. Fetch existing VT report (1 API call)
       - If VT's last analysis is within 24h → use it directly
       - If stale or not found → submit for fresh scan
    2. Submit + poll for fresh result (~2+ API calls)
    """
    url = url.strip().rstrip("/")
    print(f"\n{'─'*60}")
    print(f"Checking: {url}")

    report = fetch_report(url)

    if report and is_within_24h(report.get("last_vt_analysis")):
        print(f"  [OK] VT report is fresh (within 24h), using it.")
        report["url"]    = url
        report["source"] = "existing_report"
        return report

    if report:
        print(f"  [STALE] VT report is older than 24h — submitting for rescan...")
    else:
        print(f"  [NEW] URL not in VT database — submitting for first scan...")

    analysis_id = submit_url(url)
    if not analysis_id:
        return {"url": url, "error": "Failed to submit URL for scanning"}

    result = poll_analysis(analysis_id)
    if result:
        result["url"]    = url
        result["source"] = "fresh_scan"
        return result

    # Polling timed out — try fetching the report one more time
    print(f"  [FALLBACK] Trying to fetch report after scan submission...")
    report = fetch_report(url)
    if report:
        report["url"]    = url
        report["source"] = "post_submit_fetch"
        return report

    return {"url": url, "error": "Scan submitted but result unavailable"}

# ─── Display ──────────────────────────────────────────────────────────────────

def print_result(entry: dict):
    """Pretty-print a single result to the terminal."""
    if "error" in entry:
        print(f"  ⚠️  ERROR: {entry['error']}")
        return

    risk = (
        "🔴 DANGEROUS"  if entry.get("malicious", 0) > 0  else
        "🟡 SUSPICIOUS" if entry.get("suspicious", 0) > 0 else
        "🟢 CLEAN"
    )

    print(f"  Status   : {risk}")
    print(f"  Malicious: {entry.get('malicious',0)}  "
          f"Suspicious: {entry.get('suspicious',0)}  "
          f"Harmless: {entry.get('harmless',0)}  "
          f"Undetected: {entry.get('undetected',0)}  "
          f"(of {entry.get('total_vendors',0)} vendors)")
    print(f"  VT scan  : {entry.get('last_vt_analysis', 'unknown')}  "
          f"[{entry.get('source', '?')}]")

    flagged = entry.get("flagged_by", {})
    if flagged:
        print(f"  Flagged by ({len(flagged)} vendors):")
        for vendor, verdict in flagged.items():
            print(f"    • {vendor}: {verdict}")
    else:
        print(f"  Flagged by: none")


def print_summary(results: list[dict]):
    dangerous  = [r for r in results if r.get("malicious", 0) > 0]
    suspicious = [r for r in results if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0]
    clean      = [r for r in results if not r.get("malicious") and not r.get("suspicious") and "error" not in r]
    errors     = [r for r in results if "error" in r]

    print(f"\n{'═'*60}")
    print(f"  SUMMARY  ({len(results)} URLs checked)")
    print(f"{'═'*60}")
    print(f"  🔴 Dangerous  : {len(dangerous)}")
    print(f"  🟡 Suspicious : {len(suspicious)}")
    print(f"  🟢 Clean      : {len(clean)}")
    print(f"  ⚠️  Errors     : {len(errors)}")

    if dangerous:
        print(f"\n  Dangerous URLs:")
        for r in dangerous:
            print(f"    • {r['url']}  ({r.get('malicious',0)} vendors)")

    if suspicious:
        print(f"\n  Suspicious URLs:")
        for r in suspicious:
            print(f"    • {r['url']}  ({r.get('suspicious',0)} vendors)")

# ─── Appeal trigger ──────────────────────────────────────────────────────────

def run_appeals(result: dict):
    """
    After a VT check, trigger appeal submissions for any flagging vendors
    that have a matching module in vendors/.
    """
    flagged_by = result.get("flagged_by", {})
    if not flagged_by:
        return

    url = result.get("url", "")

    matched   = []
    unmatched = []

    for vendor in flagged_by:
        module = VENDOR_MODULES.get(vendor.lower())
        if module:
            matched.append((vendor, module))
        else:
            unmatched.append(vendor)

    if not matched:
        print(f"\n  [APPEAL] No appeal modules available for flagging vendors:")
        for v in unmatched:
            print(f"    • {v}")
        print(f"  [APPEAL] Add vendor modules to vendors/ folder to enable automation.")
        return

    print(f"\n  [APPEAL] Starting appeals for {len(matched)} vendor(s)...")
    if unmatched:
        print(f"  [APPEAL] Skipping {len(unmatched)} vendor(s) with no module: {', '.join(unmatched)}")

    for vendor, module in matched:
        print(f"\n  [APPEAL] ── Vendor: {vendor} ──")
        try:
            module.submit(url=url, flagged_by=flagged_by)
        except Exception as e:
            print(f"  [APPEAL] ERROR during {vendor} appeal: {e}")

# ─── CLI ──────────────────────────────────────────────────────────────────────

def cmd_check_all():
    if not Path(URLS_FILE).exists():
        print(f"[ERROR] '{URLS_FILE}' not found.")
        sys.exit(1)

    urls = json.loads(Path(URLS_FILE).read_text()).get("urls", [])
    if not urls:
        print("[INFO] No URLs found in urls.json.")
        return

    _load_vendor_modules()

    print(f"\n{'═'*60}")
    print(f"  VirusTotal URL Checker + Appeal Automation")
    print(f"  URLs to check   : {len(urls)}")
    print(f"  Vendor modules  : {len(VENDOR_MODULES)}")
    print(f"  Rate limit      : {RATE_LIMIT_SLEEP}s between API calls")
    print(f"{'═'*60}")

    results = []
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}]", end=" ")
        result = check_url(url)
        print_result(result)
        results.append(result)

        # ── Immediately run appeals for this URL before moving to next ──
        run_appeals(result)

    print_summary(results)


def cmd_check_single(url: str):
    _load_vendor_modules()
    print(f"\n{'═'*60}")
    print(f"  VirusTotal URL Checker — Single URL")
    print(f"{'═'*60}")
    result = check_url(url)
    print_result(result)
    run_appeals(result)

# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal URL checker")
    parser.add_argument("--url", help="Check a single URL")
    args = parser.parse_args()

    if args.url:
        cmd_check_single(args.url)
    else:
        cmd_check_all()