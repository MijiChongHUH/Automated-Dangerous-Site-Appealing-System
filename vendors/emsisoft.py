"""
vendors/emsisoft.py
===================
Selenium automation for Emsisoft false positive submission.
Form URL: https://www.emsisoft.com/en/help/contact/

How the Emsisoft form works
────────────────────────────
The category list is rendered as <label> wrappers around hidden
<input type="radio"> buttons — NOT clickable <li> elements.

  <label for="category-false-positive" tabindex="0">
    <input type="radio" id="category-false-positive"
           name="category" value="false-positive">
    <span class="name">False positive</span>
    <span class="info">report a wrongly detected file or URL</span>
  </label>

Strategy:
  1. Click the <label for="category-false-positive"> to select the
     "False positive" radio button.
  2. Wait for the product sub-list to appear, then click the <label>
     whose radio value is "other" (or whose text contains "Other").
  3. Wait for the form fields (name / email / subject / message) to
     become visible, then fill and auto-submit.

No Enter-press is needed before filling — the page transition is
handled by waiting for visibility of #message instead.

Vendor name in VirusTotal: "Emsisoft"

Dependencies
────────────
  pip install selenium webdriver-manager
"""

import json
import time
from datetime import datetime
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.keys import Keys
    from selenium.common.exceptions import (
        TimeoutException,
        InvalidSessionIdException,
        WebDriverException,
    )
except ImportError:
    print("[ERROR] Selenium not installed. Run: pip install selenium webdriver-manager")
    raise

try:
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("[ERROR] webdriver-manager not installed. Run: pip install webdriver-manager")
    raise


FORM_URL    = "https://www.emsisoft.com/en/help/contact/"
VENDOR_NAME = "Emsisoft"
TEMPLATE    = json.loads(Path("template.json").read_text())

# ── Timing ────────────────────────────────────────────────────────────────────
_T_FIELD       = 0.05
_T_AFTER_CLICK = 0.8    # wait after clicking a radio label for JS to react
_T_PAGE_LOAD   = 15
_T_APPEAR      = 12

# ── Field selectors (active after category + product are selected) ─────────────
SEL_NAME    = [(By.NAME, 'name'),    (By.CSS_SELECTOR, 'input[placeholder*="name" i]')]
SEL_EMAIL   = [(By.NAME, 'email'),   (By.CSS_SELECTOR, 'input[type="email"]')]
SEL_SUBJECT = [
    (By.NAME, 'subject'),
    (By.ID, 'subject'),
    (By.CSS_SELECTOR, 'input[placeholder*="subject" i]'),
    (By.CSS_SELECTOR, 'input[placeholder*="message about" i]'),
]
SEL_MESSAGE = [(By.ID, 'message'), (By.NAME, 'message'), (By.CSS_SELECTOR, 'textarea')]
SEL_SUBMIT  = [
    (By.CSS_SELECTOR, 'button[type="submit"]'),
    (By.CSS_SELECTOR, 'input[type="submit"]'),
]
SEL_SUCCESS = [
    (By.XPATH,
     '//*[contains(text(),"We will be in touch") or '
     'contains(text(),"message was delivered") or '
     'contains(text(),"Thank you for reaching out") or '
     'contains(text(),"successfully")]'),
    (By.CSS_SELECTOR, '.contact-success, [class*="success"]'),
]

# ── JS helpers ────────────────────────────────────────────────────────────────
_JS_SET_INPUT = """
    var el=arguments[0],val=arguments[1];
    var s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
    if(s)s.set.call(el,val);else el.value=val;
    ['input','change','blur'].forEach(function(e){
        el.dispatchEvent(new Event(e,{bubbles:true}));});
"""
_JS_SET_TEXTAREA = """
    var el=arguments[0],val=arguments[1];
    var s=Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype,'value');
    if(s)s.set.call(el,val);else el.value=val;
    ['input','change','blur'].forEach(function(e){
        el.dispatchEvent(new Event(e,{bubbles:true}));});
"""

# ─── Module-level shared state ────────────────────────────────────────────────
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


# ─── Driver helpers ───────────────────────────────────────────────────────────
def _make_driver(headless: bool = False):
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--window-size=1280,900")
    drv = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    drv.execute_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
    return drv


def _is_driver_alive(driver) -> bool:
    if driver is None:
        return False
    try:
        _ = driver.title
        return True
    except Exception:
        return False


def _ensure_driver(headless: bool = False):
    global _shared_driver
    if _is_driver_alive(_shared_driver):
        return _shared_driver, False
    if _shared_driver is not None:
        print(f"  [APPEAL] Browser session lost — respawning Chrome...")
        try:
            _shared_driver.quit()
        except Exception:
            pass
    drv = _make_driver(headless)
    _shared_driver = drv
    print(f"  [APPEAL] New Chrome session ready.")
    return drv, True


# ─── Domain + field builders ──────────────────────────────────────────────────

def _clean_domain(url: str) -> str:
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _build_fields(domain: str, flagged_by: dict) -> dict:
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")

    # Prefer vendor-specific keys; fall back to generic shared keys
    subject_tpl = TEMPLATE.get("emsisoft_subject_template",
                               TEMPLATE["subject_template"])
    body_tpl    = TEMPLATE.get("emsisoft_body_template",
                               TEMPLATE["body_template"])
    return {
        "name":    TEMPLATE["company_name"],
        "email":   TEMPLATE["requestor_email"],
        "subject": subject_tpl.format(domain=domain),
        "message": body_tpl.format(
                       vendor_name    = VENDOR_NAME,
                       domain         = domain,
                       detection_type = detection_str,
                       date_flagged   = date_flagged,
                   ),
    }


# ─── Field helpers ────────────────────────────────────────────────────────────

def _find_element(driver, selectors, timeout=6):
    for by, sel in selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((by, sel))
            )
            return el, (by, sel)
        except Exception:
            continue
    return None, None


def _fill(driver, selectors, value, label):
    el, matched = _find_element(driver, selectors, timeout=_T_APPEAR)
    if el is None:
        print(f"  [APPEAL] WARNING : '{label}' not found — fill manually")
        return
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(_T_FIELD)
        js = _JS_SET_TEXTAREA if el.tag_name.lower() == "textarea" else _JS_SET_INPUT
        driver.execute_script(js, el, value)
        actual = driver.execute_script("return arguments[0].value||'';", el)
        if value[:20] in actual:
            print(f"  [APPEAL] Filled  : {label}  ({matched[1]})")
        else:
            # JS didn't stick — type it
            driver.execute_script("arguments[0].focus();", el)
            ActionChains(driver).click(el)\
                .key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL)\
                .send_keys(Keys.DELETE).perform()
            ActionChains(driver).send_keys(value).perform()
            time.sleep(0.2)
            print(f"  [APPEAL] Filled  : {label}  (typed, {matched[1]})")
    except Exception as e:
        print(f"  [APPEAL] WARNING : fill failed for '{label}': {e}")


# ─── Radio-button category + product selection ────────────────────────────────

def _click_radio_label(driver, radio_id: str = None, radio_value: str = None,
                        label_text: str = None, context: str = "", timeout: int = 10) -> bool:
    """
    Click the <label> associated with a radio button.

    Tries, in order:
      1. label[for="<radio_id>"]          — exact for= match
      2. input[value="<radio_value>"] → parent label
      3. <label> whose visible text contains label_text (case-insensitive)

    Clicks via JS to avoid "element not interactable" on hidden radios.
    Returns True on success.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            label_el = None

            # Strategy 1: label[for=id]
            if radio_id:
                els = driver.find_elements(By.CSS_SELECTOR, f'label[for="{radio_id}"]')
                if els:
                    label_el = els[0]

            # Strategy 2: find radio by value, then its parent label
            if label_el is None and radio_value:
                radios = driver.find_elements(
                    By.CSS_SELECTOR,
                    f'input[type="radio"][value="{radio_value}"]'
                )
                for r in radios:
                    try:
                        parent = driver.execute_script(
                            "return arguments[0].closest('label');", r
                        )
                        if parent:
                            label_el = parent
                            break
                    except Exception:
                        pass

            # Strategy 3: text scan over all labels
            if label_el is None and label_text:
                target = label_text.lower()
                for lbl in driver.find_elements(By.TAG_NAME, "label"):
                    txt = (lbl.text or "").lower().strip()
                    if target in txt:
                        label_el = lbl
                        break

            if label_el is not None:
                driver.execute_script(
                    "arguments[0].scrollIntoView({block:'center'}); arguments[0].click();",
                    label_el
                )
                display_text = (label_el.text or "").strip().split("\n")[0]
                print(f"  [APPEAL] {context}: '{display_text}'")
                time.sleep(_T_AFTER_CLICK)
                return True

        except Exception:
            pass

        time.sleep(0.3)

    print(f"  [APPEAL] WARNING : Could not click radio for '{context}'.")
    return False


def _select_category_and_product(driver) -> bool:
    """
    Step 1 — Click the 'False positive' radio label.
    Step 2 — Click the 'Other' product radio label that appears next.
    Step 3 — Wait for the message textarea to confirm the form is ready.

    No manual Enter press needed — we wait for DOM changes instead.
    """
    # ── Wait for radio buttons to appear ─────────────────────────────────────
    print(f"  [APPEAL] Waiting for category radio buttons...")
    try:
        WebDriverWait(driver, _T_PAGE_LOAD).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, 'input[type="radio"][name="category"]')
            )
        )
    except TimeoutException:
        print(f"  [APPEAL] WARNING : Category radio buttons did not appear in time.")
        # Fall through — maybe they loaded slowly

    # ── Click "False positive" radio label ───────────────────────────────────
    cat_ok = _click_radio_label(
        driver,
        radio_id    = "category-false-positive",
        radio_value = "false-positive",
        label_text  = "false positive",
        context     = "Category selected",
        timeout     = 10,
    )
    if not cat_ok:
        print(f"  [APPEAL] 👉  Please click 'False positive' in the browser, then press Enter.")
        input()

    # ── Wait for product radio buttons to appear ──────────────────────────────
    print(f"  [APPEAL] Waiting for product radio buttons...")
    product_appeared = False
    try:
        # Product radios appear inside a section that was hidden before
        WebDriverWait(driver, _T_APPEAR).until(
            EC.visibility_of_element_located(
                (By.CSS_SELECTOR, 'input[type="radio"][name="product"]')
            )
        )
        product_appeared = True
    except TimeoutException:
        # Some page variants use a different name attribute
        try:
            WebDriverWait(driver, 4).until(
                EC.visibility_of_element_located(
                    (By.CSS_SELECTOR, 'input[type="radio"]:not([name="category"])')
                )
            )
            product_appeared = True
        except TimeoutException:
            pass

    if not product_appeared:
        print(f"  [APPEAL] WARNING : Product list did not appear — trying anyway.")

    # ── Click "Other" product radio label ────────────────────────────────────
    prod_ok = _click_radio_label(
        driver,
        radio_value = "other",
        label_text  = "other",
        context     = "Product selected",
        timeout     = 8,
    )
    if not prod_ok:
        print(f"  [APPEAL] 👉  Please click 'Other' in the product list, then press Enter.")
        input()

    # ── Wait for the message textarea (confirms form is fully visible) ─────────
    print(f"  [APPEAL] Waiting for form fields to appear...")
    try:
        WebDriverWait(driver, _T_APPEAR).until(
            EC.visibility_of_element_located((By.ID, "message"))
        )
        print(f"  [APPEAL] Form fields ready.")
        return True
    except TimeoutException:
        try:
            WebDriverWait(driver, 4).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "textarea"))
            )
            print(f"  [APPEAL] Form fields ready (textarea fallback).")
            return True
        except TimeoutException:
            print(f"  [APPEAL] WARNING : Form fields slow — proceeding anyway.")
            return True


def _try_auto_submit(driver) -> bool:
    """Click Submit and watch for the success banner. Returns True if confirmed."""
    el, _ = _find_element(driver, SEL_SUBMIT, timeout=5)
    if el is None:
        print(f"  [APPEAL] WARNING : Submit button not found.")
        return False
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        driver.execute_script("arguments[0].click();", el)
        print(f"  [APPEAL] Submit clicked.")
    except Exception as e:
        print(f"  [APPEAL] WARNING : Submit click failed: {e}")
        return False

    for by, sel in SEL_SUCCESS:
        try:
            WebDriverWait(driver, 12).until(EC.visibility_of_element_located((by, sel)))
            print(f"  [APPEAL] ✅  Success — submission confirmed.")
            return True
        except TimeoutException:
            continue
    print(f"  [APPEAL] Success banner not detected within 12 s.")
    return False


def _debug_dump_fields(driver):
    print("\n  [DEBUG] ── Fields on page ──")
    for el in driver.find_elements(By.CSS_SELECTOR, "input,textarea,select,button,label"):
        name  = el.get_attribute("name")  or ""
        id_   = el.get_attribute("id")    or ""
        typ   = el.get_attribute("type")  or ""
        value = el.get_attribute("value") or ""
        for_  = el.get_attribute("for")   or ""
        if name or id_ or for_:
            disp = driver.execute_script(
                "return window.getComputedStyle(arguments[0]).display;", el)
            print(f"  [DEBUG]  <{el.tag_name}> type={typ:<12} display={disp:<12} "
                  f"name={name:<25} id={id_:<30} for={for_:<30} value={value[:20]}")
    print("  [DEBUG] ── End ──\n")


# ─── Main submit ──────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Fill and auto-submit the Emsisoft false positive form.

    Steps:
      1. Load FORM_URL
      2. Click 'False positive' radio label → product list appears
      3. Click 'Other' radio label → form fields appear
      4. Fill Name, Email, Subject, Message  (no manual Enter needed)
      5. Click Submit → wait for success banner
      6. If success banner absent → pause for manual fix
    """
    global _shared_driver

    domain = _clean_domain(url)
    fields = _build_fields(domain, flagged_by)
    print(f"\n  [APPEAL] ── Emsisoft : {domain} ──")

    using_shared = (_shared_driver is not None)

    for attempt in range(1, 3):
        try:
            driver = (_ensure_driver(headless)[0]
                      if using_shared else _make_driver(headless))

            # Always do a full page load for Emsisoft (stateful JS)
            driver.get(FORM_URL)
            print(f"  [APPEAL] Page loaded.")

            # Select category (False positive) and product (Other)
            _select_category_and_product(driver)

            if debug:
                _debug_dump_fields(driver)

            # Fill all form fields
            _fill(driver, SEL_NAME,    fields["name"],    "Name")
            _fill(driver, SEL_EMAIL,   fields["email"],   "Email")
            _fill(driver, SEL_SUBJECT, fields["subject"], "Subject")
            _fill(driver, SEL_MESSAGE, fields["message"], "Message")

            # Auto-submit
            print(f"\n  {'─'*54}")
            print(f"  [APPEAL] Fields filled for: {domain}")
            submitted = _try_auto_submit(driver)

            if not submitted:
                print(f"  [APPEAL] 👉  Please in the browser:")
                print(f"  [APPEAL]     1. Complete any CAPTCHA if shown")
                print(f"  [APPEAL]     2. Click Submit if not already clicked")
                print(f"  [APPEAL] Press Enter once done.")
                print(f"  {'─'*54}")
                input()

            return True

        except (InvalidSessionIdException, WebDriverException) as e:
            msg = str(e)
            if ("session deleted" in msg or "disconnected" in msg
                    or "invalid session" in msg.lower()):
                if attempt == 1:
                    print(f"  [APPEAL] Session lost — respawning and retrying...")
                    if using_shared:
                        try:
                            _shared_driver.quit()
                        except Exception:
                            pass
                        _shared_driver = None
                    continue
                print(f"  [APPEAL] Retry failed: {e}")
                return False
            print(f"  [APPEAL] ERROR : {e}")
            return False

        except Exception as e:
            print(f"  [APPEAL] ERROR : {e}")
            return False

        finally:
            if not using_shared and 'driver' in dir() and driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    return False