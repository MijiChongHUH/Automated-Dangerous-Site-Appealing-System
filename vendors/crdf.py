"""
vendors/crdf.py
===============
Selenium-based false positive submission for CRDF Threat Center.
Form URL: https://threatcenter.crdf.fr/false_positive.html

Form structure (confirmed via debug inspection):
  • input[name='email_address']  — email address (required)
  • input[name='multiple_urls']  — checkbox to toggle multi-URL mode
  • input[name='domainName']     — single URL input (required, default mode)
  • textarea[name='domainNames'] — multiple URLs, one per line (hidden by default)
  • textarea[name='motivations'] — reason for request (optional but we fill it)
  • input[name='tos_ag']         — terms of service checkbox (required)
  • input[id='not-robot']        — human verification checkbox (USER clicks)
  • button.btn-primary text='Send Message' — submit (USER clicks after not-robot)

Workflow:
  1. Open page in visible Chrome window.
  2. Dismiss cookie banner if present.
  3. Fill email address.
  4. If multiple domains → check the multiple_urls checkbox, fill textarea[domainNames].
     If single domain  → fill input[domainName] directly.
  5. Fill motivations textarea.
  6. Check the terms of service checkbox (tos_ag) automatically.
  7. Prompt user to: (a) tick the "I'm not a robot" checkbox, (b) click Send Message.
  8. Detect success and confirm in terminal.

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
USER_WAIT_SECS = 300   # seconds for user to tick not-robot + click Send


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
    """Always visible — user must tick the not-robot checkbox."""
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
    tpl = TEMPLATE.get("crdf_body_template",
                        TEMPLATE.get("body_template", ""))
    return tpl.format(
        vendor_name    = VENDOR_NAME,
        domain         = domain,
        detection_type = detection_str,
        date_flagged   = date_flagged,
    )


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
    Fill the CRDF false positive form.
    urls: list of full URLs to submit (with https:// prefix).
    """
    wait = WebDriverWait(driver, 25)

    print(f"  [APPEAL] Loading form: {FORM_URL}")
    driver.get(FORM_URL)

    try:
        wait.until(EC.presence_of_element_located(
            (By.CSS_SELECTOR, "form#false-positive-form")
        ))
        time.sleep(3)
    except TimeoutException:
        print(f"  [APPEAL] ❌  Form did not load in time.")
        return False

    _dismiss_cookies(driver)

    if debug:
        print(f"  [DEBUG] Title: {driver.title}")

    sender_email = TEMPLATE["requestor_email"]
    # Use body of first domain for motivations (all domains share same reason)
    first_domain = _clean_domain(urls[0]) if urls else ""
    body         = _build_body(first_domain, flagged_by)

    # ── Email ─────────────────────────────────────────────────────────────────
    email_field = _safe_find(driver, "input[name='email_address']")
    if not email_field:
        print(f"  [APPEAL] ❌  Email field not found — aborting.")
        return False
    email_field.clear()
    email_field.send_keys(sender_email)
    print(f"  [APPEAL] ✏️   Email    : {sender_email}")

    # ── Single vs Multiple URLs ───────────────────────────────────────────────
    if len(urls) > 1:
        # Check the "Submit multiple URLs" checkbox to reveal the textarea
        print(f"  [APPEAL] 🔘  Enabling multiple URL mode ({len(urls)} URLs)...")
        _check_checkbox(driver, "input[name='multiple_urls']", "Multiple URLs")
        time.sleep(1)   # wait for the textarea to become visible

        # Fill the domainNames textarea (one URL per line, max 5)
        domain_names_field = _safe_find(driver, "textarea[name='domainNames']")
        if not domain_names_field:
            # Try JS to make it visible if still hidden
            driver.execute_script(
                "document.getElementById('multiple-urls-container').style.display = 'block';"
            )
            time.sleep(0.5)
            domain_names_field = _safe_find(driver, "textarea[name='domainNames']")

        if domain_names_field:
            urls_text = "\n".join(urls[:5])   # max 5 per CRDF rules
            domain_names_field.clear()
            domain_names_field.send_keys(urls_text)
            print(f"  [APPEAL] ✏️   URLs     : {len(urls[:5])} URL(s) entered")
            if debug:
                print(f"  [DEBUG] URLs:\n{urls_text}")
        else:
            print(f"  [APPEAL] ⚠️   Multiple URL textarea not found — falling back to first URL only.")
            # Fall through to single URL mode
            single_field = _safe_find(driver, "input[name='domainName']")
            if single_field:
                single_field.clear()
                single_field.send_keys(urls[0])
                print(f"  [APPEAL] ✏️   URL      : {urls[0]} (fallback single)")
    else:
        # Single URL mode — fill domainName input directly
        domain_field = _safe_find(driver, "input[name='domainName']")
        if not domain_field:
            print(f"  [APPEAL] ❌  Domain URL field not found — aborting.")
            return False
        domain_field.clear()
        domain_field.send_keys(urls[0])
        print(f"  [APPEAL] ✏️   URL      : {urls[0]}")

    # ── Motivations / Reason ──────────────────────────────────────────────────
    motivations_field = _safe_find(driver, "textarea[name='motivations']")
    if motivations_field:
        motivations_field.clear()
        motivations_field.send_keys(body)
        print(f"  [APPEAL] ✏️   Reason   : ({len(body)} chars)")
        if debug:
            print(f"  [DEBUG] Motivations:\n{body}\n")
    else:
        print(f"  [APPEAL] ℹ️   Motivations field not found (optional).")

    # ── Terms of Service checkbox (auto-check) ────────────────────────────────
    _check_checkbox(driver, "input[name='tos_ag']", "Terms of Service")

    # ── Scroll to the not-robot checkbox so user can see it ───────────────────
    try:
        not_robot = driver.find_element(By.CSS_SELECTOR, "input#not-robot")
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", not_robot)
    except Exception:
        # Scroll to submit button as fallback
        try:
            submit_btn = driver.find_element(
                By.CSS_SELECTOR, "button.btn-primary"
            )
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", submit_btn)
        except Exception:
            pass

    # ── Prompt user ───────────────────────────────────────────────────────────
    print(f"")
    print(f"  [APPEAL] ✅  Form filled. Browser window is ready.")
    print(f"  [APPEAL] 👉  Please do the following in the browser:")
    print(f"  [APPEAL]     1. Tick the 'I'm not a robot' checkbox")
    print(f"  [APPEAL]     2. Click the 'Send Message' button")
    print(f"  [APPEAL]     Waiting up to {USER_WAIT_SECS}s...")
    print(f"")

    # ── Detect success ────────────────────────────────────────────────────────
    initial_url = driver.current_url
    end_time    = time.time() + USER_WAIT_SECS

    while time.time() < end_time:
        time.sleep(1)

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
                return True
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
                    return True
            except Exception:
                pass

    print(f"  [APPEAL] ⚠️   No success signal after {USER_WAIT_SECS}s.")
    print(f"  [APPEAL]     If you clicked Send Message, the form likely submitted.")
    return False


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