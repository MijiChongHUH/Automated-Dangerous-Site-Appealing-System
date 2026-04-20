import json
import time
import hashlib
import base64
import argparse
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
BASE_URL         = _require_env("VT_BASE_URL")
URLS_FILE        = os.getenv("URLS_FILE", "urls.json")
CACHE_MAX_AGE    = timedelta(hours=int(os.getenv("CACHE_MAX_AGE_HOURS", "168")))  # 7 days (168 hours) default
NO_WAIT_MODE     = os.getenv("NO_WAIT_MODE", "false").lower() == "true"  # Submit and don't wait for results
STRICT_RATE_LIMIT = os.getenv("STRICT_RATE_LIMIT", "false").lower() == "true"  # Only enforce rate limit on concurrent

HEADERS = {
    "x-apikey": API_KEY,
    "Accept":   "application/json",
}

# ─── Rate Limiter ───────────────────────────────────────────────────────────

class RateLimiter:
    """Thread-safe rate limiter for VirusTotal API calls."""
    def __init__(self, calls_per_minute: int = 4):
        self.calls_per_minute = calls_per_minute
        self.interval = 60.0 / calls_per_minute
        self.last_call = 0.0
        self.lock = threading.Lock()

    def wait_if_needed(self, skip_on_first: bool = False):
        """Wait until it's safe to make another API call.
        
        Args:
            skip_on_first: If True, skip rate limiting on first call (no prior activity).
        """
        with self.lock:
            # Skip rate limiting if this is the first call and skip_on_first is True
            if skip_on_first and self.last_call == 0.0:
                self.last_call = time.time()
                return
            
            # Only enforce strict rate limiting if configured or multiple concurrent tasks
            if not STRICT_RATE_LIMIT:
                self.last_call = time.time()
                return
            
            # Strict rate limiting (for concurrent mode)
            now = time.time()
            time_since_last = now - self.last_call
            if time_since_last < self.interval:
                sleep_time = self.interval - time_since_last
                print(f"  [RATE] Respecting VT 4 req/min limit (~{sleep_time:.1f}s)...")
                time.sleep(sleep_time)
            self.last_call = time.time()

# Global rate limiter instance
rate_limiter = RateLimiter(calls_per_minute=4)

# ─── Vendor appeal registry ───────────────────────────────────────────────────
# Loaded from vendors/__init__.py — edit that file to enable/disable vendors.

VENDOR_MODULES: dict = {}

def _load_vendor_modules():
    """
    Import vendors/__init__.py and copy its VENDOR_MODULES registry.
    Vendors are enabled/disabled by editing vendors/__init__.py directly.
    """
    global VENDOR_MODULES
    try:
        # Ensure the project root is on sys.path so `vendors` is importable
        project_root = str(Path(__file__).parent.resolve())
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        import vendors as _vendors_pkg
        VENDOR_MODULES = _vendors_pkg.VENDOR_MODULES
        print(f"  [VENDOR] Registry loaded from vendors/__init__.py")
    except ImportError as e:
        print(f"  [VENDOR] WARNING : Could not import vendors package: {e}")
        print(f"  [VENDOR]           Make sure vendors/__init__.py exists.")
    except Exception as e:
        print(f"  [VENDOR] ERROR loading vendors: {e}")

# ─── Helpers ──────────────────────────────────────────────────────────────────

def url_to_id(url: str) -> str:
    """
    VirusTotal URL ID = URL-safe base64(sha256(url)) with no padding.
    """
    digest = hashlib.sha256(url.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def url_to_id_variants(url: str) -> list:
    """
    Return all ID variants to try for a given input:
      - as-is
      - with https:// prefix (if no scheme present)
      - with http://  prefix (if no scheme present)
    """
    variants = [url]
    if not url.startswith("http://") and not url.startswith("https://"):
        variants.append("https://" + url)
        variants.append("http://"  + url)
    return [url_to_id(v) for v in variants]


def wait(skip_first: bool = False):
    """Rate limit API calls using the global rate limiter.
    
    Args:
        skip_first: If True, skip rate limiting on the very first API call.
    """
    rate_limiter.wait_if_needed(skip_on_first=skip_first)


def is_within_24h(timestamp_str: str) -> bool:
    """Return True if the ISO timestamp is within the last 24 hours."""
    if not timestamp_str:
        return False
    try:
        ts = datetime.fromisoformat(timestamp_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts) < timedelta(hours=24)
    except Exception:
        return False


def is_within_cache_age(timestamp_str: str) -> bool:
    """Return True if the ISO timestamp is within the cache age window."""
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

def fetch_report(url: str, is_first_call: bool = False) -> dict | None:
    """
    GET /urls/{id} — fetch VT's stored report for a URL.
    Tries all ID variants so bare domains are handled correctly.
    """
    ids = url_to_id_variants(url)
    print(f"  [API] Fetching VT report...")

    for url_id in ids:
        resp = requests.get(f"{BASE_URL}/urls/{url_id}", headers=HEADERS, timeout=20)
        wait(skip_first=is_first_call)
        is_first_call = False  # Only skip rate limit on truly first call

        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            return parse_analysis(attrs)

        if resp.status_code in (400, 404):
            continue

        print(f"  [WARN] Unexpected response {resp.status_code}: {resp.text[:200]}")

    return None


def submit_url(url: str) -> str | None:
    """POST /urls — submit URL for a fresh scan. Returns analysis ID or None."""
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


def poll_analysis(analysis_id: str, timeout_secs: int = 60) -> dict | None:
    """GET /analyses/{id} — poll until completed with exponential backoff.
    
    Args:
        analysis_id: The VT analysis ID to poll.
        timeout_secs: Maximum time to wait for results (default 60s).
    """
    base_wait = 5  # Start with 5 seconds
    max_attempts = min(8, max(3, (timeout_secs // 5)))  # Adaptive attempts based on timeout
    start_time = time.time()

    for attempt in range(1, max_attempts + 1):
        wait_time = min(base_wait * (2 ** (attempt - 1)), 60)  # Exponential backoff, max 60s
        
        # Check if we'd exceed timeout
        if time.time() - start_time + wait_time > timeout_secs:
            print(f"  [API] Polling timeout ({timeout_secs}s) approaching, stopping.")
            break
        
        print(f"  [API] Polling result (attempt {attempt}/{max_attempts}, waiting {wait_time}s)...")
        time.sleep(wait_time)

        resp = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS,
            timeout=20,
        )
        # Only wait between requests, not after the last one
        if attempt < max_attempts:
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

    print(f"  [WARN] Polling timed out after {max_attempts} attempts.")
    return None

# ─── Core checker ─────────────────────────────────────────────────────────────

def check_url(url: str, wait_for_results: bool = True) -> dict:
    """Check a single URL against VirusTotal with optimized scanning.
    
    Args:
        url: URL to check.
        wait_for_results: If False, submit and return immediately (NO_WAIT_MODE).
    """
    url = url.strip().rstrip("/")
    print(f"\n{'─'*60}")
    print(f"Checking: {url}")

    # First API call - can skip rate limit on very first check if NO_WAIT_MODE
    report = fetch_report(url, is_first_call=(NO_WAIT_MODE or not wait_for_results))

    if report and is_within_24h(report.get("last_vt_analysis")):
        print(f"  [OK] VT report is fresh (within 24h), using it.")
        report["url"]    = url
        report["source"] = "existing_report"
        return report

    # Check if we should use cached report
    if report and is_within_cache_age(report.get("last_vt_analysis")):
        cache_hours = int(CACHE_MAX_AGE.total_seconds()/3600)
        print(f"  [OK] VT report is within cache window ({cache_hours}h), using it.")
        report["url"]    = url
        report["source"] = "cached_report"
        return report
    
    if report:
        print(f"  [STALE] VT report is older than cache window — submitting for rescan...")
    else:
        print(f"  [NEW] URL not in VT database — submitting for scan...")

    analysis_id = submit_url(url)
    if not analysis_id:
        return {"url": url, "error": "Failed to submit URL for scanning"}

    # NO_WAIT_MODE: submit and return immediately
    if NO_WAIT_MODE or not wait_for_results:
        print(f"  [SUBMITTED] Scan submitted (NO_WAIT_MODE - not waiting for results)")
        return {
            "url": url,
            "source": "submitted_pending",
            "status": "pending",
            "analysis_id": analysis_id,
            "note": "Scan submitted. Results will be available later."
        }

    # Normal mode: wait for results with shorter timeout
    result = poll_analysis(analysis_id, timeout_secs=45)
    if result:
        result["url"]    = url
        result["source"] = "fresh_scan"
        return result

    print(f"  [FALLBACK] Trying to fetch report after scan submission...")
    time.sleep(5)  # Reduced from 30s
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
    that have a matching module in VENDOR_MODULES.
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
        print(f"\n  [APPEAL] No appeal modules active for flagging vendors:")
        for v in unmatched:
            print(f"    • {v}")
        print(f"  [APPEAL] Enable vendor modules in vendors/__init__.py.")
        return

    print(f"\n  [APPEAL] Starting appeals for {len(matched)} vendor(s)...")
    if unmatched:
        print(f"  [APPEAL] Skipping {len(unmatched)} vendor(s) with no active module: "
              f"{', '.join(unmatched)}")

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

    # Check if concurrent processing is enabled
    concurrent = os.getenv("CONCURRENT_CHECKING", "false").lower() == "true"
    max_workers = min(int(os.getenv("MAX_WORKERS", "2")), len(urls))

    print(f"\n{'═'*60}")
    print(f"  VirusTotal URL Checker + Appeal Automation")
    print(f"  URLs to check   : {len(urls)}")
    print(f"  Active vendors  : {len(VENDOR_MODULES)}")
    print(f"  Rate limit      : 4 calls/minute")
    print(f"  Cache age       : {CACHE_MAX_AGE}")
    if concurrent:
        print(f"  Concurrent      : Yes (max {max_workers} workers)")
    else:
        print(f"  Concurrent      : No (sequential)")
    print(f"{'═'*60}")

    if concurrent and len(urls) > 1:
        results = check_urls_concurrent(urls, max_workers)
    else:
        results = []
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}]", end=" ")
            result = check_url(url)
            print_result(result)
            results.append(result)
            run_appeals(result)

    print_summary(results)


def check_urls_concurrent(urls: list[str], max_workers: int) -> list[dict]:
    """Check multiple URLs concurrently with coordinated rate limiting."""
    results = [None] * len(urls)  # Pre-allocate to maintain order

    def check_single_with_index(index: int, url: str):
        print(f"\n[{index+1}/{len(urls)}] Checking: {url}")
        result = check_url(url)
        print_result(result)
        run_appeals(result)
        results[index] = result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_single_with_index, i, url) for i, url in enumerate(urls)]
        for future in as_completed(futures):
            future.result()  # Wait for all to complete

    return results


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