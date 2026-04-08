"""
vendors/netcraft.py
===================
API-based false positive submission for Netcraft.
Endpoint: POST https://report.netcraft.com/api/v3/report/mistake

No browser or Selenium required — Netcraft exposes a clean public REST API
for reporting incorrectly blocked URLs. This module submits directly via
requests and confirms success from the HTTP response.

How it works
────────────
  POST /api/v3/report/mistake
  Content-Type: application/json

  {
    "email": "<reporter email>",
    "url":   "https://example.com",
    "reason": "<explanation text>"
  }

  Success → HTTP 200, body may contain a confirmation message or be empty.
  Failure → HTTP 4xx/5xx with an error body.

After submission the module also POSTs to /api/v3/report/urls to
simultaneously request that Netcraft re-scan the URL and reconsider its
classification — this is the same endpoint the Netcraft web UI uses when
you click "Report a mistake" on a flagged URL page.

Vendor name in VirusTotal: "Netcraft"

Dependencies
────────────
  pip install requests          # already required by checker.py
  No additional dependencies.

template.json keys used
────────────────────────
  requestor_email               — your e-mail address (required)
  netcraft_reason_template      — optional; falls back to body_template
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' not installed. Run: pip install requests")
    raise


VENDOR_NAME   = "Netcraft"
_API_BASE     = "https://report.netcraft.com/api/v3"
_MISTAKE_URL  = f"{_API_BASE}/report/mistake"
_REPORT_URL   = f"{_API_BASE}/report/urls"

TEMPLATE = json.loads(Path("template.json").read_text())

_HEADERS = {
    "Content-Type": "application/json",
    "Accept":        "application/json",
    "User-Agent":    "Mozilla/5.0 (compatible; FalsePositiveReporter/1.0)",
}

# ─── Shared state (kept for interface consistency with Selenium modules) ───────
_shared_driver = None   # not used; Netcraft needs no browser


def set_shared_driver(driver):
    """No-op: Netcraft uses the REST API, no browser needed."""
    pass


def close_shared_driver():
    """No-op: Netcraft uses the REST API, no browser needed."""
    pass


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    """Strip scheme and trailing slash to get a bare domain."""
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _ensure_scheme(url: str) -> str:
    """Netcraft's API requires a full URL with scheme."""
    url = url.strip().rstrip("/")
    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url
    return url


def _build_reason(domain: str, flagged_by: dict) -> str:
    """
    Build the reason/message string from template.json.
    Uses netcraft_reason_template if present, otherwise body_template.
    """
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")

    template_str = TEMPLATE.get("netcraft_reason_template",
                                TEMPLATE["body_template"])
    return template_str.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


# ─── API calls ────────────────────────────────────────────────────────────────

def _post_mistake(url_with_scheme: str, email: str, reason: str) -> bool:
    """
    POST /api/v3/report/mistake — report a URL as incorrectly blocked.
    Returns True on HTTP 200, False otherwise.
    """
    payload = {
        "email":  email,
        "url":    url_with_scheme,
        "reason": reason,
    }
    try:
        resp = requests.post(
            _MISTAKE_URL,
            headers=_HEADERS,
            json=payload,
            timeout=20,
        )
        if resp.status_code == 200:
            body = ""
            try:
                body = resp.json().get("message", "") or resp.text[:120]
            except Exception:
                body = resp.text[:120]
            print(f"  [APPEAL] ✅  Mistake report accepted (HTTP 200).")
            if body:
                print(f"  [APPEAL]     Response: {body}")
            return True
        else:
            print(f"  [APPEAL] ❌  Mistake report failed — HTTP {resp.status_code}")
            print(f"  [APPEAL]     Response: {resp.text[:300]}")
            return False
    except requests.RequestException as e:
        print(f"  [APPEAL] ERROR : Network error on /report/mistake: {e}")
        return False


def _post_rescan(url_with_scheme: str, email: str, reason: str) -> bool:
    """
    POST /api/v3/report/urls — request a fresh Netcraft scan of the URL.
    This is a secondary submission that triggers reclassification.
    Returns True on HTTP 200.
    """
    payload = {
        "email":  email,
        "reason": reason,
        "urls": [{"url": url_with_scheme}],
    }
    try:
        resp = requests.post(
            _REPORT_URL,
            headers=_HEADERS,
            json=payload,
            timeout=20,
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                uuid = data.get("uuid", "")
                msg  = data.get("message", "")
                print(f"  [APPEAL] ✅  Rescan request accepted (HTTP 200).")
                if uuid:
                    print(f"  [APPEAL]     Submission UUID : {uuid}")
                    print(f"  [APPEAL]     Submission link : "
                          f"https://report.netcraft.com/submission/{uuid}")
                if msg:
                    print(f"  [APPEAL]     Message         : {msg}")
            except Exception:
                print(f"  [APPEAL] ✅  Rescan accepted. Response: {resp.text[:120]}")
            return True
        else:
            print(f"  [APPEAL] ⚠️   Rescan request — HTTP {resp.status_code}: "
                  f"{resp.text[:200]}")
            return False
    except requests.RequestException as e:
        print(f"  [APPEAL] WARNING : Network error on /report/urls: {e}")
        return False


# ─── Main submit ──────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a Netcraft false-positive (mistake) report via the public REST API.

    Two requests are made:
      1. POST /api/v3/report/mistake  — flags the URL as incorrectly blocked
      2. POST /api/v3/report/urls     — requests a fresh scan / reclassification

    Both use the same email and reason. The second request is best-effort
    (a failure there does not cause submit() to return False if step 1 succeeded).

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Ignored (no browser used).
        debug      : If True, prints full request payloads.

    Returns:
        True if the mistake report was accepted (HTTP 200), False otherwise.
    """
    domain          = _clean_domain(url)
    url_with_scheme = _ensure_scheme(url)
    email           = TEMPLATE["requestor_email"]
    reason          = _build_reason(domain, flagged_by)

    print(f"\n  [APPEAL] ── Netcraft (API) : {domain} ──")
    print(f"  [APPEAL] Endpoint : {_MISTAKE_URL}")
    print(f"  [APPEAL] URL      : {url_with_scheme}")
    print(f"  [APPEAL] Email    : {email}")

    if debug:
        print(f"  [DEBUG] Reason:\n{reason}\n")

    # ── Step 1: Report as incorrectly blocked ─────────────────────────────────
    print(f"  [APPEAL] Step 1/2 — Submitting mistake report...")
    ok = _post_mistake(url_with_scheme, email, reason)

    if not ok:
        # Retry once after a short delay (transient network errors)
        print(f"  [APPEAL] Retrying in 5 s...")
        time.sleep(5)
        ok = _post_mistake(url_with_scheme, email, reason)

    if not ok:
        print(f"  [APPEAL] Mistake report failed after retry — skipping rescan.")
        return False

    # ── Step 2: Request a fresh scan (best-effort) ────────────────────────────
    print(f"  [APPEAL] Step 2/2 — Requesting URL rescan...")
    time.sleep(1)   # brief pause between the two requests
    _post_rescan(url_with_scheme, email, reason)

    print(f"  [APPEAL] Done for: {domain}")
    return True