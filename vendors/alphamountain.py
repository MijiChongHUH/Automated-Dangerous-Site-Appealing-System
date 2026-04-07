"""
vendors/alphamountain.py
========================
Selenium automation for alphaMountain.ai false positive submission.
Form URL: https://www.alphamountain.ai/false-positive/

Crash recovery
──────────────
Chrome can die mid-run for several reasons:
  • User accidentally closes the browser window
  • Chrome auto-updates and kills the existing process
  • OS memory pressure kills it
  • DevTools disconnect on slow / sleeping machines

All of these surface as InvalidSessionIdException or WebDriverException
with "session deleted" / "disconnected" in the message.

This module catches those errors in submit(), calls _ensure_driver() which:
  1. Tests the current driver with a lightweight title check
  2. If dead → quietly quits it, spawns a fresh Chrome, does a full
     page-load + iframe switch, and retries filling the form once.
  3. If the retry also fails → reports the error and moves on to the
     next URL (does not kill the whole run).

Speed optimisations
────────────────────
  1. Shared Chrome driver  — one browser for all URLs, injected via
     set_shared_driver().  Saves 3–5 s cold-start per URL.
  2. Form reset instead of reload  — between URLs the form fields are
     cleared via JS, no page reload.  Saves 4–8 s per URL.
  3. Tighter sleep constants  — inter-field pauses 0.05 s, Redactor
     ready-poll timeout 5 s (warm driver is ready in <0.5 s).

Field map
─────────
  Email    → input[type="email"]
  Name     → helpdesk_ticket[name]
  Subject  → helpdesk_ticket[subject]
  Body     → div[contenteditable="true"]  — ActionChains typing
  Website  → helpdesk_ticket[custom_field][cf_website_1555433]
  Category → helpdesk_ticket[custom_field][cf_suggested_category_1555433]

Dependencies
────────────
  pip install selenium webdriver-manager
  pip install pyperclip          # optional clipboard fallback
  # Linux: sudo apt install xclip  (needed by pyperclip)

Vendor name in VirusTotal: "alphaMountain.ai"
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
    from selenium.webdriver.support.ui import WebDriverWait, Select
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


FORM_URL    = "https://www.alphamountain.ai/false-positive/"
VENDOR_NAME = "alphaMountain.ai"
TEMPLATE    = json.loads(Path("template.json").read_text())

# ── Timing constants (tune here) ──────────────────────────────────────────────
_T_FIELD            = 0.05   # pause after filling each regular field
_T_CE_CLICK         = 0.10   # pause after clicking Redactor editor
_T_AFTER_TYPE       = 0.30   # pause after ActionChains typing
_T_REDACTOR         = 0.20   # poll interval while waiting for Redactor init
_T_REDACTOR_TIMEOUT = 5      # max seconds to wait for Redactor init

# ── Selectors ─────────────────────────────────────────────────────────────────

SEL_EMAIL = [
    (By.NAME,         'helpdesk_ticket[requester]'),
    (By.ID,           'helpdesk_ticket_requester'),
    (By.CSS_SELECTOR, 'input[type="email"]'),
]
SEL_NAME = [
    (By.NAME,         'helpdesk_ticket[name]'),
    (By.ID,           'helpdesk_ticket_name'),
    (By.CSS_SELECTOR, 'input[placeholder*="Name"]'),
]
SEL_SUBJECT = [
    (By.NAME,         'helpdesk_ticket[subject]'),
    (By.ID,           'helpdesk_ticket_subject'),
]
SEL_BODY_CE = [
    # Most specific: the visible editor div (class="redactor_editor", underscore).
    # The form also has a hidden getPasteImage div (contenteditable, height:0px)
    # which generic selectors find first — we must skip it.
    (By.CSS_SELECTOR, 'div.redactor_editor[contenteditable="true"]'),
    (By.CSS_SELECTOR, 'div.redactor_editor'),
    # Fallbacks (visibility-filtered in _find_redactor_editor)
    (By.CSS_SELECTOR, 'div.redactor-box > div[contenteditable="true"]'),
    (By.CSS_SELECTOR, 'div.redactor-box [contenteditable="true"]'),
    (By.CSS_SELECTOR, 'div[contenteditable="true"]'),
]
SEL_BODY_TEXTAREA = [
    (By.ID,           'helpdesk_ticket_ticket_body_attributes_description_html'),
    (By.CSS_SELECTOR, 'textarea[id*="description_html"]'),
    (By.CSS_SELECTOR, 'textarea[id*="body_attributes"]'),
    (By.NAME,         'helpdesk_ticket[description]'),
]
SEL_DISPUTED_WEBSITE = [
    (By.NAME,         'helpdesk_ticket[custom_field][cf_website_1555433]'),
    (By.CSS_SELECTOR, 'input[name*="cf_website"]'),
]
SEL_CATEGORY = [
    (By.NAME,         'helpdesk_ticket[custom_field][cf_suggested_category_1555433]'),
    (By.CSS_SELECTOR, 'select[name*="cf_suggested_category"]'),
]

# ── JS snippets ───────────────────────────────────────────────────────────────

_JS_SET_INPUT = """
    var el=arguments[0],val=arguments[1];
    var s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
    if(s)s.set.call(el,val);else el.value=val;
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
"""
_JS_SET_TEXTAREA = """
    var el=arguments[0],val=arguments[1];
    var s=Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype,'value');
    if(s)s.set.call(el,val);else el.value=val;
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
"""
_JS_RESET_FORM = """
    document.querySelectorAll('input[type="text"],input[type="email"]').forEach(function(el){
        var s=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
        if(s)s.set.call(el,'');else el.value='';
        el.dispatchEvent(new Event('input',{bubbles:true}));
    });
    document.querySelectorAll('select').forEach(function(el){
        el.selectedIndex=0;
        el.dispatchEvent(new Event('change',{bubbles:true}));
    });
    document.querySelectorAll('div[contenteditable="true"]').forEach(function(el){
        el.innerHTML='<p><br></p>';
        el.dispatchEvent(new Event('input',{bubbles:true}));
    });
    document.querySelectorAll('textarea[id*="description"],textarea[id*="body"]').forEach(function(el){
        var s=Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype,'value');
        if(s)s.set.call(el,'');else el.value='';
    });
"""

# ─── Module-level shared state ────────────────────────────────────────────────

_shared_driver  = None
_iframe_entered = False   # True after first successful iframe switch in shared mode


def set_shared_driver(driver):
    """Inject a pre-created Chrome driver from checker.py."""
    global _shared_driver, _iframe_entered
    _shared_driver  = driver
    _iframe_entered = False


def close_shared_driver():
    """Quit the shared driver and clear module state."""
    global _shared_driver, _iframe_entered
    if _shared_driver:
        try:
            _shared_driver.quit()
        except Exception:
            pass
    _shared_driver  = None
    _iframe_entered = False


# ─── Driver factory + health check ───────────────────────────────────────────

def _make_driver(headless: bool = False):
    """Spawn a fresh Chrome WebDriver with anti-detection flags."""
    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--window-size=1280,900")
    drv = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), options=opts
    )
    drv.execute_script(
        "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
    )
    return drv


def _is_driver_alive(driver) -> bool:
    """
    Return True if the driver session is still usable.
    Calls driver.title — a trivially cheap DevTools round-trip.
    """
    if driver is None:
        return False
    try:
        _ = driver.title
        return True
    except Exception:
        return False


def _ensure_driver(headless: bool = False) -> tuple:
    """
    Return (driver, is_fresh) where is_fresh=True means a new session was created.
    """
    global _shared_driver, _iframe_entered

    if _is_driver_alive(_shared_driver):
        return _shared_driver, False

    if _shared_driver is not None:
        print(f"  [APPEAL] Browser session lost — respawning Chrome...")
        try:
            _shared_driver.quit()
        except Exception:
            pass

    new_driver      = _make_driver(headless)
    _shared_driver  = new_driver
    _iframe_entered = False
    print(f"  [APPEAL] New Chrome session ready.")
    return new_driver, True


# ─── Domain + field builders ─────────────────────────────────────────────────
# FIX: These two functions were missing from the original alphamountain.py,
#      causing a NameError crash before any browser interaction happened.

def _clean_domain(url: str) -> str:
    """Strip scheme and trailing slash to get a bare domain."""
    domain = url.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain


def _build_fields(domain: str, flagged_by: dict) -> dict:
    """
    Build the dict of form field values from template.json.

    Uses vendor-specific keys if present, otherwise falls back to the
    generic subject_template / body_template keys so a single template.json
    works for all vendors without duplication.

    Required template keys (generic fallback):
      company_name, requestor_email, subject_template, body_template

    Optional vendor-specific overrides:
      alphamountain_subject_template, alphamountain_body_template,
      alphamountain_category  (defaults to "Gambling" then "Business")
    """
    detection_types = list(flagged_by.values()) if flagged_by else ["Malicious"]
    detection_str   = " / ".join(sorted(set(d.capitalize() for d in detection_types)))
    date_flagged    = datetime.now().strftime("%m/%d/%Y")

    # Prefer vendor-specific keys; fall back to generic shared keys
    subject_tpl = TEMPLATE.get("alphamountain_subject_template",
                               TEMPLATE["subject_template"])
    body_tpl    = TEMPLATE.get("alphamountain_body_template",
                               TEMPLATE["body_template"])
    # Category: vendor-specific → suggested_category → hard default
    category    = TEMPLATE.get("alphamountain_category",
                  TEMPLATE.get("suggested_category", "Business"))

    return {
        "email":    TEMPLATE["requestor_email"],
        "name":     TEMPLATE["company_name"],
        "subject":  subject_tpl.format(domain=domain),
        "body":     body_tpl.format(
                        vendor_name    = VENDOR_NAME,
                        domain         = domain,
                        detection_type = detection_str,
                        date_flagged   = date_flagged,
                    ),
        "domain":   domain,
        "category": category,
    }


# ─── Page / iframe setup ─────────────────────────────────────────────────────

def _switch_to_freshdesk_iframe(driver, timeout: int = 15) -> bool:
    driver.switch_to.default_content()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for iframe in driver.find_elements(By.TAG_NAME, "iframe"):
            src = iframe.get_attribute("src") or ""
            if any(k in src for k in ["freshdesk", "freshservice", "freshworks", "feedback_widget"]):
                try:
                    driver.switch_to.frame(iframe)
                    print(f"  [APPEAL] Switched to iframe: {src[:80]}")
                    return True
                except Exception:
                    continue
        time.sleep(0.3)
    # Fallback — first iframe
    for iframe in driver.find_elements(By.TAG_NAME, "iframe"):
        try:
            driver.switch_to.frame(iframe)
            print(f"  [APPEAL] Using fallback: first iframe.")
            return True
        except Exception:
            continue
    return False


def _load_form(driver, timeout: int = 15) -> bool:
    """Navigate to the form URL and switch into the Freshdesk iframe."""
    driver.get(FORM_URL)
    print(f"  [APPEAL] Page loaded. Locating Freshdesk iframe...")
    if not _switch_to_freshdesk_iframe(driver, timeout=timeout):
        print(f"  [APPEAL] ERROR : Freshdesk iframe not found.")
        return False
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "input, textarea"))
        )
    except TimeoutException:
        pass
    return True


def _reset_form(driver):
    """Clear all form fields in-place (no page reload)."""
    try:
        driver.execute_script(_JS_RESET_FORM)
        time.sleep(0.2)
        print(f"  [APPEAL] Form reset (no reload).")
    except Exception as e:
        print(f"  [APPEAL] Form reset failed ({e}) — reloading page instead...")
        _load_form(driver, timeout=15)


# ─── Field helpers ────────────────────────────────────────────────────────────

def _find_element(driver, selectors: list, timeout: int = 6):
    for by, sel in selectors:
        try:
            el = WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((by, sel))
            )
            return el, (by, sel)
        except (TimeoutException, Exception):
            continue
    return None, None


def _fill(driver, selectors, value, label):
    el, matched = _find_element(driver, selectors, timeout=6)
    if el is None:
        print(f"  [APPEAL] WARNING : '{label}' not found — fill manually")
        return
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(_T_FIELD)
        js = _JS_SET_TEXTAREA if el.tag_name.lower() == "textarea" else _JS_SET_INPUT
        driver.execute_script(js, el, value)
        actual = driver.execute_script("return arguments[0].value || '';", el)
        if value[:20] in actual:
            print(f"  [APPEAL] Filled  : {label}  ({matched[1]})")
        else:
            print(f"  [APPEAL] WARNING : '{label}' may not have stuck")
    except Exception as e:
        print(f"  [APPEAL] WARNING : fill failed for '{label}': {e}")


def _select(driver, selectors, value, field_label):
    el, matched = _find_element(driver, selectors, timeout=6)
    if el is None:
        print(f"  [APPEAL] WARNING : Dropdown '{field_label}' not found")
        return
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        time.sleep(_T_FIELD)
        sel_obj = Select(el)
        for method, fn in [("text",  lambda: sel_obj.select_by_visible_text(value)),
                            ("value", lambda: sel_obj.select_by_value(value))]:
            try:
                fn()
                print(f"  [APPEAL] Selected: {field_label} → {value}  (by {method})")
                return
            except Exception:
                pass
        result = driver.execute_script(
            "var e=arguments[0],v=arguments[1].toLowerCase();"
            "for(var i=0;i<e.options.length;i++){"
            "if(e.options[i].text.toLowerCase().includes(v)||"
            "e.options[i].value.toLowerCase().includes(v)){"
            "e.selectedIndex=i;"
            "e.dispatchEvent(new Event('change',{bubbles:true}));"
            "return e.options[i].text;}}"
            "return null;",
            el, value
        )
        if result:
            print(f"  [APPEAL] Selected: {field_label} → {result}  (JS partial)")
        else:
            print(f"  [APPEAL] WARNING : No option matched '{value}' for '{field_label}'")
    except Exception as e:
        print(f"  [APPEAL] WARNING : Dropdown error for '{field_label}': {e}")


def _find_redactor_editor(driver, timeout: int = 10):
    """
    Return the VISIBLE Redactor editor div, skipping the hidden getPasteImage div.

    The alphaMountain Freshdesk widget has two contenteditable divs:
      1. div[rel="getPasteImage"]  — style="width:50px;height:0px;overflow:hidden"
         Hidden paste target — must be skipped.
      2. div.redactor_editor       — style="height:131px"  ← the real editor

    Strategy (in order):
      a) div.redactor_editor[contenteditable="true"]  — class name with underscore
      b) Any contenteditable div whose offsetHeight > 10 px
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Strategy a: exact class match (fastest)
        els = driver.find_elements(
            By.CSS_SELECTOR, 'div.redactor_editor[contenteditable="true"]'
        )
        for el in els:
            try:
                h = driver.execute_script("return arguments[0].offsetHeight;", el)
                if h and int(h) > 10:
                    return el
            except Exception:
                pass

        # Strategy b: any visible contenteditable div
        els = driver.find_elements(By.CSS_SELECTOR, 'div[contenteditable="true"]')
        for el in els:
            try:
                h = driver.execute_script("return arguments[0].offsetHeight;", el)
                if h and int(h) > 10:
                    return el
            except Exception:
                pass

        time.sleep(_T_REDACTOR)
    return None


def _wait_for_redactor_ready(driver) -> bool:
    """Return True when the visible Redactor editor has rendered its initial <p>."""
    deadline = time.time() + _T_REDACTOR_TIMEOUT
    while time.time() < deadline:
        el = _find_redactor_editor(driver, timeout=0.5)
        if el is not None:
            try:
                count = driver.execute_script("return arguments[0].children.length;", el)
                if count and int(count) > 0:
                    return True
            except Exception:
                pass
        time.sleep(_T_REDACTOR)
    return False


def _fill_redactor_body(driver, value: str):
    """
    Fill the Redactor rich-text editor (div.redactor_editor) via ActionChains.

    Falls back to JS innerHTML injection, then clipboard paste, then the
    hidden textarea — each is verified before moving to the next.
    """
    ce_el = _find_redactor_editor(driver, timeout=_T_REDACTOR_TIMEOUT)
    if ce_el is None:
        print(f"  [APPEAL] WARNING : Redactor editor not found — textarea fallback...")
        _fill(driver, SEL_BODY_TEXTAREA, value, "Body (textarea fallback)")
        return

    # ── Attempt 1: JS innerHTML set (instant, no typing needed) ──────────────
    try:
        # Convert plain text newlines → <br> so the editor renders them
        html_value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_value = "<p>" + html_value.replace("\n", "<br>") + "</p>"
        driver.execute_script("""
            var el = arguments[0], html = arguments[1];
            el.focus();
            el.innerHTML = html;
            el.dispatchEvent(new Event('input',  {bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
        """, ce_el, html_value)
        time.sleep(0.2)
        actual = driver.execute_script(
            "return arguments[0].innerText || arguments[0].textContent || '';", ce_el
        )
        if value[:15].strip() in actual:
            print(f"  [APPEAL] Filled  : Body/Description  (JS innerHTML)")
            print(f"           Preview : {actual[:70].strip()!r}...")
            return
        print(f"  [APPEAL] JS innerHTML inconclusive — trying ActionChains...")
    except Exception as e:
        print(f"  [APPEAL] JS innerHTML failed ({e}) — trying ActionChains...")

    # ── Attempt 2: ActionChains keyboard typing ───────────────────────────────
    try:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", ce_el)
        ActionChains(driver).click(ce_el).perform()
        time.sleep(_T_CE_CLICK)
        # Select-all + delete existing placeholder text
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
        ActionChains(driver).send_keys(Keys.DELETE).perform()
        time.sleep(0.1)

        lines = value.split("\n")
        chain = ActionChains(driver)
        for i, line in enumerate(lines):
            if line:
                chain.send_keys(line)
            if i < len(lines) - 1:
                chain.key_down(Keys.SHIFT).send_keys(Keys.ENTER).key_up(Keys.SHIFT)
        chain.perform()
        time.sleep(_T_AFTER_TYPE)

        actual = driver.execute_script(
            "return arguments[0].innerText || arguments[0].textContent || '';", ce_el
        )
        if value[:15].strip() in actual:
            print(f"  [APPEAL] Filled  : Body/Description  (ActionChains)")
            print(f"           Preview : {actual[:70].strip()!r}...")
            return
        print(f"  [APPEAL] ActionChains inconclusive — trying clipboard...")
    except Exception as e:
        print(f"  [APPEAL] ActionChains failed ({e}) — trying clipboard...")

    # ── Attempt 3: clipboard paste ────────────────────────────────────────────
    _fill_redactor_clipboard(driver, ce_el, None, value)


def _fill_redactor_clipboard(driver, ce_el, _unused, value: str):
    """Paste value into the Redactor editor via clipboard (pyperclip)."""
    try:
        import pyperclip
        pyperclip.copy(value)
        ActionChains(driver).click(ce_el).perform()
        time.sleep(0.1)
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
        ActionChains(driver).key_down(Keys.CONTROL).send_keys('v').key_up(Keys.CONTROL).perform()
        time.sleep(0.3)
        actual = driver.execute_script("return arguments[0].innerText||'';", ce_el)
        if value[:15].strip() in actual:
            print(f"  [APPEAL] Filled  : Body/Description  (clipboard paste)")
        else:
            print(f"  [APPEAL] WARNING : Clipboard paste inconclusive — fill manually.")
    except ImportError:
        print(f"  [APPEAL] pyperclip not installed — textarea last resort.")
        _fill(driver, SEL_BODY_TEXTAREA, value, "Body (textarea last-resort)")
    except Exception as e:
        print(f"  [APPEAL] Clipboard fallback failed: {e} — fill Description manually.")


def _debug_dump_fields(driver):
    print("\n  [DEBUG] ── Fields in current frame ──")
    for el in driver.find_elements(By.CSS_SELECTOR, "input,textarea,select,div[contenteditable]"):
        name = el.get_attribute("name") or ""
        id_  = el.get_attribute("id")   or ""
        ce   = el.get_attribute("contenteditable") or ""
        if name or id_ or ce == "true":
            disp = driver.execute_script(
                "return window.getComputedStyle(arguments[0]).display;", el
            )
            print(f"  [DEBUG]  <{el.tag_name}> display={disp:<12} name={name:<50} id={id_}")
    print("  [DEBUG] ── End ──\n")


# ─── Core fill routine (separated for retry logic) ───────────────────────────

def _fill_all_fields(driver, fields: dict, debug: bool):
    """Fill every form field."""
    if debug:
        _debug_dump_fields(driver)
    _fill(driver,   SEL_EMAIL,            fields["email"],    "Email")
    _fill(driver,   SEL_NAME,             fields["name"],     "Name")
    _fill(driver,   SEL_SUBJECT,          fields["subject"],  "Subject")
    _fill_redactor_body(driver,           fields["body"])
    _fill(driver,   SEL_DISPUTED_WEBSITE, fields["domain"],   "Disputed Website")
    _select(driver, SEL_CATEGORY,         fields["category"], "Category")


# ─── Main submit ──────────────────────────────────────────────────────────────

def submit(url: str, flagged_by: dict, headless: bool = False, debug: bool = False) -> bool:
    """
    Fill the alphaMountain false positive form for one URL.
    """
    global _shared_driver, _iframe_entered

    domain = _clean_domain(url)
    fields = _build_fields(domain, flagged_by)

    print(f"\n  [APPEAL] ── alphaMountain : {domain} ──")

    using_shared = (_shared_driver is not None)

    for attempt in range(1, 3):
        try:
            if using_shared:
                driver, is_fresh = _ensure_driver(headless)
            else:
                driver   = _make_driver(headless)
                is_fresh = True

            if is_fresh or not _iframe_entered:
                if not _load_form(driver, timeout=15):
                    return False
                if using_shared:
                    _iframe_entered = True
            else:
                _reset_form(driver)

            _fill_all_fields(driver, fields, debug)

            print(f"\n  {'─'*54}")
            print(f"  [APPEAL] ✅  Fields filled for: {domain}")
            print(f"  [APPEAL] 👉  In the browser:")
            print(f"  [APPEAL]     1. Check all fields look correct")
            print(f"  [APPEAL]     2. Solve the reCAPTCHA")
            print(f"  [APPEAL]     3. Click Submit")
            print(f"  [APPEAL] Press Enter here once submitted.")
            print(f"  {'─'*54}")
            input()

            return True

        except (InvalidSessionIdException, WebDriverException) as e:
            msg = str(e)
            if "session deleted" in msg or "disconnected" in msg or "invalid session" in msg.lower():
                if attempt == 1:
                    print(f"\n  [APPEAL] Browser session lost mid-fill — respawning and retrying...")
                    if using_shared:
                        try:
                            _shared_driver.quit()
                        except Exception:
                            pass
                        _shared_driver  = None
                        _iframe_entered = False
                    continue
                else:
                    print(f"  [APPEAL] Retry also failed: {e}")
                    return False
            else:
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