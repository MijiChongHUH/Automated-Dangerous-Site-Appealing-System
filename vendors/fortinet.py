"""
vendors/fortiguard.py
=====================
Selenium-based false positive (malicious URL appeal) submission for FortiGuard.
Form URL: https://www.fortiguard.com/faq/malurl

Form fields (confirmed via page inspection):
  • URL          — input (required)
  • Name         — input (required)
  • Email        — input (required)
  • Company Name — input (required)
  • Comment      — textarea (optional, we fill it)
  • Human verification widget (reCAPTCHA or similar) — USER clicks manually
  • Submit button — USER clicks manually after completing verification

Workflow:
  1. Open the page in a visible Chrome window.
  2. Auto-fill all fields (URL, Name, Email, Company, Comment).
  3. Scroll the verification widget into view.
  4. Pause and prompt user to: (a) complete the human check, (b) click Submit.
  5. Detect success response and confirm in terminal.

Vendor name in VirusTotal: "Fortinet"

Dependencies
────────────
  pip install selenium webdriver-manager

template.json keys used
────────────────────────
  requestor_email            — email field (required)
  requestor_name             — name field (falls back to company_name)
  company_name               — company name field (required)
  body_template              — comment body fallback
  fortiguard_body_template   — dedicated comment body (preferred)
    Placeholders: {domain}, {vendor_name}, {detection_type}, {date_flagged}
"""

import json
import time
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


VENDOR_NAME    = "Fortinet"
FORM_URL       = "https://www.fortiguard.com/faq/malurl"
TEMPLATE       = json.loads(Path("template.json").read_text())
USER_WAIT_SECS = 180   # seconds for user to complete captcha + click Submit


# ─── Shared driver ────────────────────────────────────────────────────────────

_shared_driver = None


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
    """Always visible — user must complete human verification manually."""
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
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
    tpl = TEMPLATE.get("fortiguard_body_template",
                        TEMPLATE.get("body_template", ""))
    return tpl.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


def _safe_find(driver, css: str):
    """Return a displayed element or None."""
    try:
        el = driver.find_element(By.CSS_SELECTOR, css)
        return el if el.is_displayed() else None
    except NoSuchElementException:
        return None


def _fill_field(el, value: str):
    """Clear and fill a field instantly."""
    el.clear()
    el.send_keys(value)


# ─── Cookie banner ────────────────────────────────────────────────────────────

def _reject_cookies(driver):
    """Reject/decline cookie consent banner if present."""
    time.sleep(1)
    reject_keywords = ("reject", "decline", "deny", "necessary only",
                       "essential only", "refuse", "no, thanks")
    for btn in driver.find_elements(By.TAG_NAME, "button"):
        txt = (btn.text or "").strip().lower()
        if any(kw in txt for kw in reject_keywords) and btn.is_displayed():
            try:
                btn.click()
                print(f"  [APPEAL] 🍪  Cookie banner rejected.")
                time.sleep(0.5)
                return
            except Exception:
                pass
    for sel in ["button[id*='reject' i]", "button[class*='reject' i]",
                "button[id*='decline' i]", "button[class*='decline' i]"]:
        try:
            el = driver.find_element(By.CSS_SELECTOR, sel)
            if el.is_displayed():
                el.click()
                print(f"  [APPEAL] 🍪  Cookie banner rejected.")
                time.sleep(0.5)
                return
        except Exception:
            pass


# ─── Core fill logic ──────────────────────────────────────────────────────────

def _fill_form(driver, domain: str, flagged_by: dict, debug: bool) -> bool:
    wait = WebDriverWait(driver, 25)

    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    try:
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "form")))
        time.sleep(3)
    except TimeoutException:
        print(f"  [APPEAL] ❌  Page did not load in time.")
        return False

    _reject_cookies(driver)

    if debug:
        print(f"  [DEBUG] Title: {driver.title}")
        for el in driver.find_elements(By.TAG_NAME, "input"):
            print(f"  [DEBUG] input    name={el.get_attribute('name')!r:25} "
                  f"id={el.get_attribute('id')!r:25} "
                  f"placeholder={el.get_attribute('placeholder')!r}")
        for el in driver.find_elements(By.TAG_NAME, "textarea"):
            print(f"  [DEBUG] textarea name={el.get_attribute('name')!r:25} "
                  f"id={el.get_attribute('id')!r:25} "
                  f"placeholder={el.get_attribute('placeholder')!r}")

    url_with_scheme = _ensure_scheme(domain)
    sender_name     = TEMPLATE.get("requestor_name",
                                    TEMPLATE.get("company_name", "BK8 Support"))
    sender_email    = TEMPLATE["requestor_email"]
    company         = TEMPLATE.get("company_name", "BK8 Support")
    body            = _build_body(domain, flagged_by)

    # ── URL ───────────────────────────────────────────────────────────────────
    url_field = (
        _safe_find(driver, "input[placeholder*='URL' i]") or
        _safe_find(driver, "input[placeholder*='IP address' i]") or
        _safe_find(driver, "input[name*='url' i]") or
        _safe_find(driver, "input[id*='url' i]")
    )
    if not url_field:
        # Fallback: first visible text input on the page
        for el in driver.find_elements(By.CSS_SELECTOR, "input[type='text']"):
            if el.is_displayed():
                url_field = el
                break
    if not url_field:
        print(f"  [APPEAL] ❌  URL field not found — aborting.")
        return False
    _fill_field(url_field, url_with_scheme)
    print(f"  [APPEAL] ✏️   URL          : {url_with_scheme}")

    # ── Name ──────────────────────────────────────────────────────────────────
    name_field = (
        _safe_find(driver, "input[placeholder*='name' i]") or
        _safe_find(driver, "input[name*='name' i]") or
        _safe_find(driver, "input[id*='name' i]")
    )
    if name_field:
        _fill_field(name_field, sender_name)
        print(f"  [APPEAL] ✏️   Name         : {sender_name}")
    else:
        print(f"  [APPEAL] ⚠️   Name field not found.")

    # ── Email ─────────────────────────────────────────────────────────────────
    email_field = (
        _safe_find(driver, "input[type='email']") or
        _safe_find(driver, "input[placeholder*='email' i]") or
        _safe_find(driver, "input[name*='email' i]") or
        _safe_find(driver, "input[id*='email' i]")
    )
    if not email_field:
        print(f"  [APPEAL] ❌  Email field not found — aborting.")
        return False
    _fill_field(email_field, sender_email)
    print(f"  [APPEAL] ✏️   Email        : {sender_email}")

    # ── Company Name ──────────────────────────────────────────────────────────
    company_field = (
        _safe_find(driver, "input[placeholder*='company' i]") or
        _safe_find(driver, "input[name*='company' i]") or
        _safe_find(driver, "input[id*='company' i]")
    )
    if company_field:
        _fill_field(company_field, company)
        print(f"  [APPEAL] ✏️   Company      : {company}")
    else:
        print(f"  [APPEAL] ⚠️   Company field not found.")

    # ── Comment ───────────────────────────────────────────────────────────────
    comment_field = (
        _safe_find(driver, "textarea[placeholder*='comment' i]") or
        _safe_find(driver, "textarea[name*='comment' i]") or
        _safe_find(driver, "textarea[id*='comment' i]") or
        _safe_find(driver, "textarea")
    )
    if comment_field:
        _fill_field(comment_field, body)
        print(f"  [APPEAL] ✏️   Comment      : ({len(body)} chars)")
        if debug:
            print(f"  [DEBUG] Body:\n{body}\n")
    else:
        print(f"  [APPEAL] ℹ️   Comment field not found (optional).")

    # ── Scroll verification widget into view ──────────────────────────────────
    # Try to find reCAPTCHA iframe or any verification widget
    for sel in ["iframe[src*='recaptcha']", "iframe[title*='recaptcha' i]",
                ".g-recaptcha", "#recaptcha", "[class*='captcha' i]",
                "[id*='captcha' i]"]:
        try:
            widget = driver.find_element(By.CSS_SELECTOR, sel)
            if widget.is_displayed():
                driver.execute_script(
                    "arguments[0].scrollIntoView({block:'center'});", widget
                )
                print(f"  [APPEAL] 🔒  Verification widget scrolled into view.")
                break
        except Exception:
            pass

    # ── Prompt user ───────────────────────────────────────────────────────────
    print(f"")
    print(f"  [APPEAL] ✅  All fields filled. Browser window is ready.")
    print(f"  [APPEAL] 👉  Please do the following in the browser:")
    print(f"  [APPEAL]     1. Complete the human verification (tick the checkbox)")
    print(f"  [APPEAL]     2. Click the Submit button")
    print(f"  [APPEAL]     Waiting up to {USER_WAIT_SECS}s...")
    print(f"")

    # ── Detect success ────────────────────────────────────────────────────────
    initial_url = driver.current_url
    end_time    = time.time() + USER_WAIT_SECS

    while time.time() < end_time:
        time.sleep(1)

        current_url = driver.current_url

        # Redirect-based success
        if current_url != initial_url:
            time.sleep(2)   # let page settle
            final_url = driver.current_url
            if any(kw in final_url.lower() for kw in ("thank", "success", "confirm", "sent")):
                print(f"  [APPEAL] ✅  Redirected to success page: {final_url}")
                return True
            if final_url != initial_url:
                print(f"  [APPEAL] ✅  Page navigated after submission: {final_url}")
                return True

        # Page text success/error keywords
        try:
            page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            success_kw = ("thank you", "successfully", "submitted", "received",
                          "under review", "we will", "has been submitted")
            error_kw   = ("error", "invalid", "required field", "please fill",
                          "failed to submit")
            if any(kw in page_text for kw in success_kw):
                print(f"  [APPEAL] ✅  Success message detected on page.")
                return True
            if any(kw in page_text for kw in error_kw):
                print(f"  [APPEAL] ❌  Error message detected — check browser.")
                return False
        except Exception:
            pass

        # Visible success element
        for sel in (".alert-success", ".success-message", ".success",
                    "[class*='success' i]", "[class*='thank' i]"):
            try:
                el = driver.find_element(By.CSS_SELECTOR, sel)
                if el.is_displayed() and el.text.strip():
                    print(f"  [APPEAL] ✅  Success element: {el.text.strip()[:100]}")
                    return True
            except Exception:
                pass

    print(f"  [APPEAL] ⚠️   No success signal detected after {USER_WAIT_SECS}s.")
    print(f"  [APPEAL]     If you submitted the form in the browser, it likely went through.")
    return False


# ─── Main entry ───────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Submit a FortiGuard malicious URL appeal via their web form.

    Auto-fills URL, Name, Email, Company and Comment fields, then
    waits for the user to complete the human verification widget
    and click Submit manually.

    Args:
        url        : The domain/URL being appealed.
        flagged_by : { vendor_name: verdict } dict from VirusTotal.
        headless   : Ignored — always visible for manual verification.
        debug      : Print all field names for troubleshooting.

    Returns:
        True if success confirmed, False on failure or timeout.
    """
    global _shared_driver

    domain     = _clean_domain(url)
    own_driver = False
    driver     = _shared_driver

    print(f"\n  [APPEAL] ── FortiGuard (Selenium / manual verify+send) : {domain} ──")
    print(f"  [APPEAL] Form URL : {FORM_URL}")
    print(f"  [APPEAL] Mode     : Auto-fill → User completes verification + clicks Submit")

    try:
        if driver is None:
            print(f"  [APPEAL] Starting Chrome driver...")
            driver     = _build_driver()
            own_driver = True

        ok = _fill_form(driver, domain, flagged_by, debug)

        if ok:
            print(f"  [APPEAL] Done for: {domain}")
            time.sleep(8)   # let user see success page before browser closes
        else:
            print(f"  [APPEAL] ❌  Failed or timed out for: {domain}")

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