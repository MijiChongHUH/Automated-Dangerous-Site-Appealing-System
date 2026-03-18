"""
VirusTotal URL Checker
======================
Reads URLs from urls.json, checks each against VirusTotal API,
and saves results to results.json.

Rate limiting:
  - Max 4 requests/minute (free tier)
  - Max 500 requests/day
  - Cached results fresher than 24h are reused (no API call made)

Usage:
  python checker.py                  # Check all URLs in urls.json
  python checker.py --url <url>      # Check a single URL
  python checker.py --report         # Print summary of latest results.json
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

# ─── Load .env ────────────────────────────────────────────────────────────────

load_dotenv()  # reads .env from current directory (or any parent)

def _require_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        print(f"[ERROR] Missing required env variable: {key}")
        print(f"        Add it to your .env file.  See .env.example for reference.")
        sys.exit(1)
    return val

# ─── Configuration ────────────────────────────────────────────────────────────

API_KEY       = _require_env("VT_API_KEY")
BASE_URL      = "https://www.virustotal.com/api/v3"
URLS_FILE     = os.getenv("URLS_FILE",    "urls.json")
RESULTS_FILE  = os.getenv("RESULTS_FILE", "results.json")
STATE_FILE    = os.getenv("STATE_FILE",   ".vt_rate_state.json")

MAX_PER_MIN   = 4
MAX_PER_DAY   = 500
_cache_hours  = int(os.getenv("CACHE_MAX_AGE_HOURS", "24"))
CACHE_MAX_AGE = timedelta(hours=_cache_hours)

HEADERS = {
    "x-apikey": API_KEY,
    "Accept":   "application/json",
}

# ─── Rate limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Persists request timestamps across runs so limits survive restarts."""

    def __init__(self, state_file: str):
        self.path = Path(state_file)
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self.minute_window = data.get("minute_window", [])
                self.day_window    = data.get("day_window", [])
            except Exception:
                self.minute_window = []
                self.day_window    = []
        else:
            self.minute_window = []
            self.day_window    = []

    def _save(self):
        self.path.write_text(json.dumps({
            "minute_window": self.minute_window,
            "day_window":    self.day_window,
        }, indent=2))

    def _now_ts(self) -> float:
        return time.time()

    def _prune(self):
        now = self._now_ts()
        self.minute_window = [t for t in self.minute_window if now - t < 60]
        self.day_window    = [t for t in self.day_window    if now - t < 86400]

    def wait_if_needed(self):
        """Block until we're allowed to make another request."""
        while True:
            self._prune()

            if len(self.day_window) >= MAX_PER_DAY:
                oldest_day = min(self.day_window)
                wait = 86400 - (self._now_ts() - oldest_day) + 1
                print(f"[RATE] Daily limit ({MAX_PER_DAY}) reached. "
                      f"Waiting {wait/3600:.1f} hours...")
                time.sleep(wait)
                continue

            if len(self.minute_window) >= MAX_PER_MIN:
                oldest_min = min(self.minute_window)
                wait = 60 - (self._now_ts() - oldest_min) + 1
                print(f"[RATE] Minute limit ({MAX_PER_MIN}) reached. "
                      f"Waiting {wait:.1f}s...")
                time.sleep(wait)
                continue

            break   # safe to proceed

    def record(self):
        now = self._now_ts()
        self.minute_window.append(now)
        self.day_window.append(now)
        self._save()

    @property
    def daily_used(self) -> int:
        self._prune()
        return len(self.day_window)

    @property
    def minute_used(self) -> int:
        self._prune()
        return len(self.minute_window)


limiter = RateLimiter(STATE_FILE)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_id(url: str) -> str:
    """VirusTotal uses URL-safe base64(sha256(url)) as the URL identifier."""
    digest = hashlib.sha256(url.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def load_results() -> dict:
    if Path(RESULTS_FILE).exists():
        try:
            return json.loads(Path(RESULTS_FILE).read_text())
        except Exception:
            pass
    return {}


def save_results(results: dict):
    Path(RESULTS_FILE).write_text(json.dumps(results, indent=2))


def is_cache_fresh(entry: dict) -> bool:
    """Return True if cached result is younger than CACHE_MAX_AGE."""
    checked_at = entry.get("checked_at")
    if not checked_at:
        return False
    try:
        ts = datetime.fromisoformat(checked_at)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - ts
        return age < CACHE_MAX_AGE
    except Exception:
        return False


def parse_analysis(attributes: dict) -> dict:
    """Extract a clean summary from VT analysis attributes."""
    stats = attributes.get("last_analysis_stats", {})
    vendors_raw = attributes.get("last_analysis_results", {})

    flagged = {
        vendor: info.get("result") or info.get("category", "unknown")
        for vendor, info in vendors_raw.items()
        if info.get("category") in ("malicious", "suspicious")
    }

    last_analysis_ts = attributes.get("last_analysis_date")
    last_analysis_str = None
    if last_analysis_ts:
        last_analysis_str = datetime.fromtimestamp(
            last_analysis_ts, tz=timezone.utc
        ).isoformat()

    return {
        "malicious":         stats.get("malicious", 0),
        "suspicious":        stats.get("suspicious", 0),
        "harmless":          stats.get("harmless", 0),
        "undetected":        stats.get("undetected", 0),
        "total_vendors":     sum(stats.values()),
        "flagged_by":        flagged,
        "last_vt_analysis":  last_analysis_str,
    }


# ─── API calls ────────────────────────────────────────────────────────────────

def fetch_existing_report(url: str) -> dict | None:
    """
    GET /urls/{id} — fetch a previously submitted report.
    Returns parsed result dict, or None if not found / error.
    Does NOT count against rate limit if it fails (we only record on success).
    """
    url_id = url_to_id(url)
    limiter.wait_if_needed()
    print(f"  [API] Fetching existing report for: {url}")

    resp = requests.get(f"{BASE_URL}/urls/{url_id}", headers=HEADERS, timeout=20)
    limiter.record()

    if resp.status_code == 200:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        result = parse_analysis(attrs)
        result["url"]        = url
        result["source"]     = "existing_report"
        result["checked_at"] = datetime.now(timezone.utc).isoformat()
        return result

    if resp.status_code == 404:
        return None   # never seen before — need to submit

    print(f"  [WARN] Unexpected status {resp.status_code} for {url}: {resp.text[:200]}")
    return None


def submit_and_fetch(url: str) -> dict:
    """
    POST /urls  → submit URL for analysis
    GET  /analyses/{id} → poll until done (up to ~60s)
    Returns parsed result dict.
    Each of the two HTTP calls is rate-limited.
    """
    # 1. Submit
    limiter.wait_if_needed()
    print(f"  [API] Submitting URL for scan: {url}")
    resp = requests.post(
        f"{BASE_URL}/urls",
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        data={"url": url},
        timeout=20,
    )
    limiter.record()

    if resp.status_code not in (200, 201):
        return {
            "url": url, "error": f"Submit failed: {resp.status_code} {resp.text[:200]}",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    analysis_id = resp.json().get("data", {}).get("id")
    if not analysis_id:
        return {
            "url": url, "error": "No analysis ID returned",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    # 2. Poll analysis result (up to 6 attempts × 10s = 60s)
    for attempt in range(6):
        time.sleep(10)
        limiter.wait_if_needed()
        print(f"  [API] Polling analysis result (attempt {attempt+1}/6)...")
        poll = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=20,
        )
        limiter.record()

        if poll.status_code != 200:
            continue

        poll_data = poll.json().get("data", {})
        status = poll_data.get("attributes", {}).get("status")
        if status == "completed":
            attrs = poll_data.get("attributes", {})
            # Build stats from results when last_analysis_stats absent
            results_raw = attrs.get("results", {})
            stats_calc  = {"malicious": 0, "suspicious": 0,
                           "harmless": 0, "undetected": 0}
            flagged = {}
            for vendor, info in results_raw.items():
                cat = info.get("category", "undetected")
                if cat in stats_calc:
                    stats_calc[cat] += 1
                if cat in ("malicious", "suspicious"):
                    flagged[vendor] = info.get("result") or cat

            result = {
                "url":              url,
                "source":           "fresh_scan",
                "checked_at":       datetime.now(timezone.utc).isoformat(),
                "last_vt_analysis": datetime.now(timezone.utc).isoformat(),
                "total_vendors":    sum(stats_calc.values()),
                "flagged_by":       flagged,
                **stats_calc,
            }
            return result

    # Timed out — fall back to fetching the report URL now
    print("  [WARN] Analysis timed out, attempting to fetch report directly...")
    report = fetch_existing_report(url)
    if report:
        report["source"] = "post_submit_fetch"
        return report

    return {
        "url": url, "error": "Analysis timed out and report unavailable",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Core checker ─────────────────────────────────────────────────────────────

def check_url(url: str, results: dict) -> dict:
    """
    Main entry for checking one URL.
    1. If we have a fresh cache entry → return it immediately (no API call).
    2. Otherwise fetch existing VT report (1 API call).
       - If found and VT's own analysis is recent → use it.
       - If not found or VT analysis is stale → submit for fresh scan.
    """
    url = url.strip().rstrip("/")

    # Cache hit
    cached = results.get(url)
    if cached and is_cache_fresh(cached):
        age_min = (
            datetime.now(timezone.utc) -
            datetime.fromisoformat(cached["checked_at"]).replace(tzinfo=timezone.utc)
        ).seconds // 60
        print(f"  [CACHE] Using cached result ({age_min}m old): {url}")
        return cached

    # Fetch existing report from VT
    report = fetch_existing_report(url)

    if report:
        # Check how fresh VT's own last analysis is
        vt_ts = report.get("last_vt_analysis")
        vt_fresh = False
        if vt_ts:
            try:
                vt_dt = datetime.fromisoformat(vt_ts)
                if vt_dt.tzinfo is None:
                    vt_dt = vt_dt.replace(tzinfo=timezone.utc)
                vt_fresh = (datetime.now(timezone.utc) - vt_dt) < CACHE_MAX_AGE
            except Exception:
                pass

        if vt_fresh:
            print(f"  [OK] VT report is fresh, using it.")
            return report
        else:
            print(f"  [STALE] VT report is older than 24h — requesting fresh scan...")
            return submit_and_fetch(url)
    else:
        # Never seen by VT before
        print(f"  [NEW] URL not in VT database — submitting for first scan...")
        return submit_and_fetch(url)


def format_result(entry: dict) -> str:
    """Pretty-print a single result entry."""
    lines = [f"\n{'─'*60}"]
    lines.append(f"URL      : {entry.get('url', 'N/A')}")
    if "error" in entry:
        lines.append(f"ERROR    : {entry['error']}")
        return "\n".join(lines)

    risk = "🔴 DANGEROUS" if entry.get("malicious", 0) > 0 else \
           "🟡 SUSPICIOUS" if entry.get("suspicious", 0) > 0 else \
           "🟢 CLEAN"

    lines.append(f"Status   : {risk}")
    lines.append(f"Malicious: {entry.get('malicious',0)}  "
                 f"Suspicious: {entry.get('suspicious',0)}  "
                 f"Harmless: {entry.get('harmless',0)}  "
                 f"Undetected: {entry.get('undetected',0)}  "
                 f"(of {entry.get('total_vendors',0)} vendors)")
    lines.append(f"Checked  : {entry.get('checked_at','?')}  "
                 f"[{entry.get('source','?')}]")

    flagged = entry.get("flagged_by", {})
    if flagged:
        lines.append(f"Flagged by ({len(flagged)}):")
        for vendor, verdict in flagged.items():
            lines.append(f"    • {vendor}: {verdict}")
    else:
        lines.append("Flagged by: none")

    return "\n".join(lines)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def cmd_check_all():
    if not Path(URLS_FILE).exists():
        print(f"[ERROR] '{URLS_FILE}' not found. Create it with a list of URLs.")
        sys.exit(1)

    urls = json.loads(Path(URLS_FILE).read_text()).get("urls", [])
    if not urls:
        print("[INFO] No URLs found in urls.json.")
        return

    results = load_results()
    print(f"\n=== VirusTotal URL Checker ===")
    print(f"URLs to check : {len(urls)}")
    print(f"API usage today: {limiter.daily_used}/{MAX_PER_DAY}")
    print(f"Rate limit    : {MAX_PER_MIN} req/min, {MAX_PER_DAY} req/day\n")

    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Checking: {url}")
        result = check_url(url, results)
        results[url] = result
        save_results(results)
        print(format_result(result))

    print(f"\n\n=== SUMMARY ===")
    dangerous  = [r for r in results.values() if r.get("malicious", 0) > 0]
    suspicious = [r for r in results.values() if r.get("malicious", 0) == 0 and r.get("suspicious", 0) > 0]
    clean      = [r for r in results.values() if not r.get("malicious") and not r.get("suspicious") and "error" not in r]
    errors     = [r for r in results.values() if "error" in r]

    print(f"  🔴 Dangerous : {len(dangerous)}")
    print(f"  🟡 Suspicious: {len(suspicious)}")
    print(f"  🟢 Clean     : {len(clean)}")
    print(f"  ⚠️  Errors    : {len(errors)}")
    print(f"\nResults saved to: {RESULTS_FILE}")
    print(f"API usage today : {limiter.daily_used}/{MAX_PER_DAY}")


def cmd_check_single(url: str):
    results = load_results()
    print(f"\n=== Checking single URL ===")
    print(f"API usage today: {limiter.daily_used}/{MAX_PER_DAY}\n")
    result = check_url(url, results)
    results[url] = result
    save_results(results)
    print(format_result(result))


def cmd_report():
    if not Path(RESULTS_FILE).exists():
        print(f"[INFO] No results file found. Run a check first.")
        return

    results = load_results()
    print(f"\n=== Report from {RESULTS_FILE} ({len(results)} URLs) ===")
    for entry in results.values():
        print(format_result(entry))


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal URL checker")
    parser.add_argument("--url",    help="Check a single URL")
    parser.add_argument("--report", action="store_true",
                        help="Print summary of saved results")
    args = parser.parse_args()

    if args.report:
        cmd_report()
    elif args.url:
        cmd_check_single(args.url)
    else:
        cmd_check_all()