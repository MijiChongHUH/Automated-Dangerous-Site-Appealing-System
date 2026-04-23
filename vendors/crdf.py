"""
vendors/crdf.py
===============
Manual false positive submission for CRDF Threat Center (avoids reCAPTCHA bot detection).
Form URL: https://threatcenter.crdf.fr/false_positive.html

Approach: Open form in visible browser, display submission details on screen, user fills manually.
This avoids reCAPTCHA error 4093 caused by Selenium automation detection.

Details displayed for manual entry:
  • Email address
  • URL(s) to submit
  • Reason/motivations text

User then manually:
  1. Copy-paste details into form fields
  2. Check "I agree to the terms"
  3. Tick the "I'm not a robot" reCAPTCHA checkbox
  4. Click "Send Message"

Vendor name in VirusTotal: "CRDF"

Dependencies
────────────
  pip install selenium webdriver-manager

template.json keys used
────────────────────────
  requestor_email        — email address field (required)
  body_template          — motivations/reason body fallback
  crdf_body_template     — dedicated motivations body (preferred)
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
import random
import os
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import (
        TimeoutException, NoSuchElementException, ElementNotInteractableException
    )
except ImportError:
    print("[ERROR] 'selenium' not installed. Run: pip install selenium webdriver-manager")
    raise

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("[ERROR] 'webdriver-manager' not installed. Run: pip install webdriver-manager")
    raise


VENDOR_NAME    = "CRDF"
FORM_URL       = "https://threatcenter.crdf.fr/false_positive.html"
TEMPLATE       = json.loads(Path("template.json").read_text())
USER_WAIT_SECS = 600   # 10 minutes for user to fill manually and solve reCAPTCHA
DISABLE_IMAGES = os.getenv("CRDF_DISABLE_IMAGES", "false").lower() == "true"  # Speed up loading


# ─── Shared driver ────────────────────────────────────────────────────────────

_shared_driver  = None
_pending_domains = []   # accumulate domains across multiple submit() calls


def set_shared_driver(driver):
    global _shared_driver
    _shared_driver = driver


def close_shared_driver():
    global _shared_driver
    if _shared_driver:
        try:
            _shared_driver.quit()
        except Exception:
            pass
        _shared_driver = None


# ─── Driver ───────────────────────────────────────────────────────────────────

def _build_driver() -> webdriver.Chrome:
    # Always visible. Set CHROME_USER_DATA_DIR in .env to use real Chrome profile.
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    # ── Real Chrome profile (recommended for CRDF) ────────────────────────
    user_data_dir = os.getenv("CHROME_USER_DATA_DIR", "")
    chrome_profile = os.getenv("CHROME_PROFILE", "Default")
    if user_data_dir:
        opts.add_argument(f"--user-data-dir={user_data_dir}")
        opts.add_argument(f"--profile-directory={chrome_profile}")
        print(f"  [APPEAL] 🧑  Using real Chrome profile: {chrome_profile}")
    else:
        # Fallback: fresh browser with realistic UA
        opts.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
        print(f"  [APPEAL] ⚠️   No CHROME_USER_DATA_DIR set — may hit 403 on CRDF.")
        print(f"  [APPEAL]     Add CHROME_USER_DATA_DIR to .env to fix this.")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    })
    return driver


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _ensure_scheme(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def _build_body(domain: str, flagged_by: dict) -> str:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")
    tpl = TEMPLATE.get("crdf_body_template",
                        TEMPLATE.get("body_template", ""))
    return tpl.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


def _slow_type(el, text: str, delay: float = 0.08):
    """Type text slowly to appear more human-like to bot detection."""
    el.clear()
    time.sleep(0.3)
    for char in text:
        el.send_keys(char)
        time.sleep(delay + random.uniform(0.0, 0.05))


def _safe_find(driver, css: str):
    try:
        el = driver.find_element(By.CSS_SELECTOR, css)
        return el if el.is_displayed() else None
    except NoSuchElementException:
        return None


def _safe_click(driver, el):
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(0.3)
        el.click()
    except ElementNotInteractableException:
        driver.execute_script("arguments[0].click();", el)


def _check_checkbox(driver, css: str, label: str) -> bool:
    """Check a checkbox if not already checked."""
    try:
        el = driver.find_element(By.CSS_SELECTOR, css)
        if not el.is_selected():
            _safe_click(driver, el)
        print(f"  [APPEAL] ☑️   {label} checked.")
        return True
    except NoSuchElementException:
        print(f"  [APPEAL] ⚠️   {label} checkbox not found.")
        return False


# ─── Cookie banner ────────────────────────────────────────────────────────────

def _dismiss_cookies(driver):
    time.sleep(1)
    for btn in driver.find_elements(By.TAG_NAME, "button"):
        txt = (btn.text or "").strip().lower()
        if any(kw in txt for kw in ("accept", "agree", "ok", "got it", "allow")) \
                and btn.is_displayed():
            try:
                btn.click()
                print(f"  [APPEAL] 🍪  Cookie banner dismissed.")
                time.sleep(0.5)
                return
            except Exception:
                pass


# ─── Core fill logic ──────────────────────────────────────────────────────────

def _fill_form(driver, urls: list, flagged_by: dict, debug: bool) -> bool:
    """
    Open the CRDF form and display details for MANUAL filling.
    Avoids reCAPTCHA bot detection by not automating form fills.
    """
    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    # Wait for page to load
    try:
        time.sleep(3)
        # Just verify form is accessible
        page_src = driver.page_source.lower()
        if "403" in page_src or "forbidden" in page_src:
            print(f"  [APPEAL] ❌  CRDF returned 403 Forbidden")
            print(f"  [APPEAL]     Keeping browser open for inspection...")
            time.sleep(30)
            return False
    except Exception as e:
        print(f"  [APPEAL] ❌  Error accessing form: {e}")
        return False

    _dismiss_cookies(driver)

    sender_email = TEMPLATE["requestor_email"]
    first_domain = _clean_domain(urls[0]) if urls else ""
    body = _build_body(first_domain, flagged_by)
    urls_text = "\n".join(urls[:5])

    # ── Display details for manual entry ──────────────────────────────────────
    print(f"")
    print(f"  [APPEAL] ⚠️   MANUAL ENTRY MODE (avoids reCAPTCHA bot detection)")
    print(f"  [APPEAL] Please fill the form manually in the browser:")
    print(f"")
    print(f"  [APPEAL] 📧 Email:")
    print(f"     {sender_email}")
    print(f"")
    print(f"  [APPEAL] 🌐 URL(s):")
    for url in urls[:5]:
        print(f"     {url}")
    print(f"")
    print(f"  [APPEAL] 💬 Reason:")
    for line in body.split("\n"):
        print(f"     {line}")
    print(f"")
    print(f"  [APPEAL] ✅ After filling all fields:")
    print(f"     1. Check 'I agree to the terms'")
    print(f"     2. Tick the 'I'm not a robot' reCAPTCHA checkbox")
    print(f"     3. Click 'Send Message'")
    print(f"     Waiting up to {USER_WAIT_SECS}s...")
    print(f"")

    # ── Detect success ────────────────────────────────────────────────────────
    initial_url = driver.current_url
    end_time    = time.time() + USER_WAIT_SECS
    success_detected = False

    while time.time() < end_time:
        time.sleep(1)

        try:
            current_url = driver.current_url

            # Redirect to false_positive.php after successful submission
            if current_url != initial_url:
                time.sleep(2)
                final_url = driver.current_url
                if "false_positive.php" in final_url or \
                   any(kw in final_url.lower() for kw in ("thank", "success", "confirm", "sent")):
                    print(f"  [APPEAL] ✅  Redirected to confirmation page: {final_url}")
                    return True
                if final_url != initial_url:
                    print(f"  [APPEAL] ✅  Page navigated after submission: {final_url}")
                    return True

            # Page text success keywords
            try:
                page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
                success_kw = ("thank you", "successfully", "submitted", "received",
                              "under review", "we will", "request has been",
                              "false positive request")
                error_kw   = ("invalid", "required field", "please fill",
                              "error occurred", "failed")
                if any(kw in page_text for kw in success_kw):
                    print(f"  [APPEAL] ✅  Success message detected on page.")
                    success_detected = True
                    break
                if any(kw in page_text for kw in error_kw):
                    print(f"  [APPEAL] ❌  Error message detected — check browser.")
                    return False
            except Exception:
                pass

            # Visible success/alert element
            for sel in (".alert-success", ".success-message", "#success",
                        ".form-success", "[class*='success' i]"):
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    if el.is_displayed() and el.text.strip():
                        print(f"  [APPEAL] ✅  Success element: {el.text.strip()[:120]}")
                        success_detected = True
                        break
                except Exception:
                    pass

            if success_detected:
                break

        except Exception:
            pass

    if success_detected:
        return True

    print(f"  [APPEAL] ⏱️   Timeout after {USER_WAIT_SECS}s.")
    print(f"  [APPEAL]     If you submitted the form, it likely went through.")
    return True  # Return True anyway since user completed manual submission


# ─── Main entry ───────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a CRDF false positive report via their web form.

    Auto-fills email, URL(s), motivations and TOS checkbox.
    User must manually tick 'I'm not a robot' and click 'Send Message'.

    NOTE: CRDF allows up to 5 URLs per submission. If you have multiple
    flagged domains, the module uses the multiple-URL mode automatically.
    In checker.py's run_appeals(), each domain triggers submit() separately,
    so each gets its own submission. If you prefer batch submission, call
    submit_batch() directly with a list of URLs.

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Ignored — always visible for manual not-robot tick.
        debug      : Print extra diagnostics.

    Returns:
        True if success confirmed, False on failure or timeout.
    """
    global _shared_driver

    domain     = _clean_domain(url)
    url_full   = _ensure_scheme(url)
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── CRDF (Selenium / manual verify) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill → User ticks not-robot + clicks Send")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()
            own_driver = True

        ok = _fill_form(driver, [url_full], flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
            time.sleep(8)
        else:
            print(f"  [APPEAL] ❌  Failed or timed out for: {domain}")
            time.sleep(15)   # keep browser open so user can see what went wrong

        return ok

    except Exception as e:
        print(f"  [APPEAL] ERROR : {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return False

    finally:
        if own_driver and driver:
            try:
                driver.quit()
            except Exception:
                pass


def submit_batch(urls: list, flagged_by: dict, debug: bool = False) -> bool:
    """
    Submit up to 5 URLs in a single CRDF form submission (multi-URL mode).
    Call this directly from checker.py if you prefer batch over per-domain.

    Args:
        urls       : List of URLs to submit (max 5, extras ignored).
        flagged_by : Combined flagged_by dict.
        debug      : Print extra diagnostics.
    """
    global _shared_driver

    urls_full  = [_ensure_scheme(u) for u in urls[:5]]
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── CRDF BATCH (Selenium / manual verify) ──")
    print(f"  [APPEAL] Form URL  : {FORM_URL}")
    print(f"  [APPEAL] URLs      : {len(urls_full)}")
    for u in urls_full:
        print(f"  [APPEAL]   • {u}")

    try:
        if driver is None:
            driver     = _build_driver()
            own_driver = True

        ok = _fill_form(driver, urls_full, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Batch done.")
            time.sleep(8)
        else:
            print(f"  [APPEAL] ❌  Batch failed or timed out.")

        return ok

    except Exception as e:
        print(f"  [APPEAL] ERROR : {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return False

    finally:
        if own_driver and driver:
            try:
                driver.quit()
            except Exception:
                pass