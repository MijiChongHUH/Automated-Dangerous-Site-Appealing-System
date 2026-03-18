"""
vendors/alphamountain.py
========================
Playwright automation for alphaMountain.ai false positive submission.
Form URL: https://www.alphamountain.ai/false-positive/

Fields filled automatically:
  - Your Email
  - Subject
  - Body / Description
  - Disputed Website
  - Suggest New Category (Gambling)

Script pauses after filling all fields so the user can:
  1. Solve the reCAPTCHA manually
  2. Review the filled form
  3. Click Submit themselves

Vendor name in VirusTotal: "alphaMountain.ai"
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
except ImportError:
    print("[ERROR] Playwright not installed. Run: pip install playwright && playwright install chromium")
    raise


FORM_URL     = "https://www.alphamountain.ai/false-positive/"
VENDOR_NAME  = "alphaMountain.ai"   # must match VirusTotal vendor key exactly
TEMPLATE     = json.loads(Path("template.json").read_text())


def _clean_domain(url: str) -> str:
    """Strip scheme and trailing slash to get bare domain."""
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _build_fields(domain: str, flagged_by: dict) -> dict:
    """Build all form field values from template + scan result."""
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(
        d.capitalize() for d in detection_types
    )))
    date_flagged = datetime.now().strftime("%m/%d/%Y")

    return {
        "email":       TEMPLATE["requestor_email"],
        "subject":     TEMPLATE["subject_template"].format(domain=domain),
        "body":        TEMPLATE["body_template"].format(
                           vendor_name    = VENDOR_NAME,
                           domain         = domain,
                           detection_type = detection_str,
                           date_flagged   = date_flagged,
                       ),
        "domain":      domain,
        "category":    TEMPLATE["suggested_category"],
        "category_id": TEMPLATE["suggested_category_id"],
    }


def submit(url: str, flagged_by: dict, headless: bool = False) -> bool:
    """
    Open the alphaMountain false positive form, fill all fields,
    then pause for the user to solve reCAPTCHA and click Submit.

    Args:
        url        : The URL/domain being disputed (from VT result)
        flagged_by : Dict of {vendor: verdict} from VT result
        headless   : Set True to run browser in background (reCAPTCHA won't work)

    Returns:
        True if form was opened and filled successfully, False on error.
    """
    domain = _clean_domain(url)
    fields = _build_fields(domain, flagged_by)

    print(f"\n  [APPEAL] Opening alphaMountain false positive form...")
    print(f"  [APPEAL] Domain  : {domain}")
    print(f"  [APPEAL] Category: {fields['category']}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless, slow_mo=300)
            page    = browser.new_page()

            # ── Navigate ──────────────────────────────────────────────────────
            page.goto(FORM_URL, wait_until="networkidle", timeout=30000)
            print(f"  [APPEAL] Page loaded.")

            # ── Fill: Email ───────────────────────────────────────────────────
            _fill_field(page, [
                "input[name='email']",
                "input[placeholder*='email' i]",
                "input[type='email']",
                "#email",
            ], fields["email"], "Email")

            # ── Fill: Subject ─────────────────────────────────────────────────
            _fill_field(page, [
                "input[name='subject']",
                "input[placeholder*='subject' i]",
                "#subject",
            ], fields["subject"], "Subject")

            # ── Fill: Body / Description ──────────────────────────────────────
            _fill_field(page, [
                "textarea[name='description']",
                "textarea[name='body']",
                "textarea[placeholder*='description' i]",
                "textarea[placeholder*='detail' i]",
                "#description",
                "textarea",
            ], fields["body"], "Body/Description", is_textarea=True)

            # ── Fill: Disputed Website ────────────────────────────────────────
            _fill_field(page, [
                "input[name*='disputed' i]",
                "input[placeholder*='disputed' i]",
                "input[placeholder*='website' i]",
                "input[placeholder*='url' i]",
                "input[placeholder*='domain' i]",
                "input[name*='url' i]",
                "input[name*='website' i]",
            ], fields["domain"], "Disputed Website")

            # ── Select: Suggest New Category ──────────────────────────────────
            _select_category(page, fields["category_id"], fields["category"])

            # ── Pause for user ─────────────────────────────────────────────────
            print(f"\n  {'─'*56}")
            print(f"  [APPEAL] ✅ All fields filled for: {domain}")
            print(f"  [APPEAL] 👉 Please:")
            print(f"  [APPEAL]    1. Solve the reCAPTCHA in the browser window")
            print(f"  [APPEAL]    2. Review the filled form")
            print(f"  [APPEAL]    3. Click the Submit button")
            print(f"  [APPEAL] Waiting... (press Enter here when done to close browser)")
            print(f"  {'─'*56}")

            input()   # wait for user to submit and press Enter

            browser.close()
            print(f"  [APPEAL] Browser closed. Appeal submitted for: {domain}")
            return True

    except PlaywrightTimeout:
        print(f"  [APPEAL] ERROR: Page load timed out for {FORM_URL}")
        return False
    except Exception as e:
        print(f"  [APPEAL] ERROR: {e}")
        return False


# ─── Field helpers ────────────────────────────────────────────────────────────

def _fill_field(page, selectors: list, value: str, label: str, is_textarea: bool = False):
    """Try each selector in order until one works."""
    for sel in selectors:
        try:
            el = page.wait_for_selector(sel, timeout=3000)
            if el:
                el.click()
                el.fill(value)
                print(f"  [APPEAL] Filled  : {label}")
                return
        except Exception:
            continue
    print(f"  [APPEAL] WARNING : Could not find field '{label}' — may need manual input")


def _select_category(page, category_id: str, category_label: str):
    """Select the Gambling category from the dropdown."""
    # Try by option value first
    selectors = [
        "select[name*='category' i]",
        "select[name*='classification' i]",
        "select[id*='category' i]",
        "select",
    ]
    for sel in selectors:
        try:
            el = page.wait_for_selector(sel, timeout=3000)
            if el:
                # Try selecting by value (data-id)
                try:
                    page.select_option(sel, value=category_label)
                    print(f"  [APPEAL] Selected: Category → {category_label}")
                    return
                except Exception:
                    pass
                # Try selecting by label text
                try:
                    page.select_option(sel, label=category_label)
                    print(f"  [APPEAL] Selected: Category → {category_label}")
                    return
                except Exception:
                    pass
        except Exception:
            continue
    print(f"  [APPEAL] WARNING : Could not select category '{category_label}' — may need manual selection")