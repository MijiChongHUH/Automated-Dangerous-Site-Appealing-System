"""
vendors/__init__.py
===================
Vendor appeal module registry — control which vendors are active here.

HOW TO USE
──────────
• To ENABLE  a vendor : uncomment its line (remove the leading #)
• To DISABLE a vendor : comment its line out  (add a leading #)

Each enabled module must expose:
  VENDOR_NAME : str   — must match the VirusTotal vendor name exactly
                        (case-insensitive matching is done by checker.py)
  submit(url, flagged_by, headless, debug) -> bool

The VENDOR_MODULES dict below is imported by checker.py. Do NOT rename it.

Template keys required in template.json
─────────────────────────────────────────
All vendors share:
  company_name        — your company / submitter name
  requestor_email     — your e-mail address

Per-vendor keys (only needed if the vendor is enabled):
  alphamountain_subject_template   — e.g. "False Positive Report: {domain}"
  alphamountain_body_template      — full message body, uses {vendor_name},
                                     {domain}, {detection_type}, {date_flagged}
  alphamountain_category           — e.g. "Business"  (Freshdesk dropdown value)

  emsisoft_subject_template        — e.g. "False Positive: {domain}"
  emsisoft_body_template           — full message body, same placeholders

  cyradar_body_template            — message body for CyRadar CF7 form
  lionic_body_template             — message body for Lionic form
  fortiguard_body_template         — comment body for FortiGuard form
  webroot_subject_template         — subject for Webroot support ticket
  webroot_body_template            — message body for Webroot support ticket

Add similar keys for each new vendor you create.
"""

# ── Import (enable) or comment-out (disable) vendors below ───────────────────

from vendors import alphamountain
from vendors import emsisoft
from vendors import cyradar
from vendors import lionic
from vendors import fortinet
from vendors import netcraft
from vendors import webroot
# from vendors import crdf

# ── Email sender — set to True to enable, False to disable ───────────────────
# When enabled, checker.py will send one email per vendor after all VT checks.
# Vendors receiving emails are configured in vendors/email_sender.py VENDOR_EMAILS.
EMAIL_SENDER_ENABLED = True

# ─────────────────────────────────────────────────────────────────────────────
# Registry — maps VT vendor name (lower-case) → module object.
# Built automatically from every module imported above; no manual editing needed
# unless a vendor's VENDOR_NAME doesn't match what VirusTotal reports.
# ─────────────────────────────────────────────────────────────────────────────

import sys as _sys

VENDOR_MODULES: dict = {}


def _register(module):
    """Register a vendor module using its VENDOR_NAME attribute."""
    name = getattr(module, "VENDOR_NAME", None)
    if name:
        VENDOR_MODULES[name.lower()] = module
    else:
        print(f"  [VENDOR] WARNING : {module.__name__} has no VENDOR_NAME — skipped.")


# Register every module that was imported above
_enabled_modules = [
    alphamountain,
    emsisoft,
    cyradar,
    lionic,
    fortinet,
    netcraft,
    webroot
    # crdf
]

for _mod in _enabled_modules:
    _register(_mod)

# Print summary at import time so checker.py startup banner is informative
print(f"  [VENDOR] Active vendors  : {len(VENDOR_MODULES)}")
for _vname in VENDOR_MODULES:
    print(f"  [VENDOR]   • {_vname}")
print(f"  [VENDOR] Email sender    : {'ENABLED' if EMAIL_SENDER_ENABLED else 'DISABLED'}")