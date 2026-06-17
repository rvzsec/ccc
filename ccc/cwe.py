"""CWE (Common Weakness Enumeration) short-name table.

NVD assigns one or more CWE IDs to most CVEs (the `weaknesses` field in the
CVE JSON). The CWE ID alone (e.g. "CWE-502") is opaque; the human-readable
name (e.g. "Deserialization of Untrusted Data") is what an operator needs
to triage at a glance.

This module is the lookup table. The notifier consults it when building the
alert title. Not a full CWE catalog - just the high-signal entries that
show up in product CVEs. Anything not in the table falls through to the
plain "CWE-XXX" identifier.

Reference: https://cwe.mitre.org/data/published/cwe_latest.pdf
"""
from __future__ import annotations

CWE_NAMES: dict[str, str] = {
    "CWE-20":   "Improper Input Validation",
    "CWE-22":   "Path Traversal",
    "CWE-77":   "Command Injection",
    "CWE-78":   "OS Command Injection",
    "CWE-79":   "Cross-site Scripting",
    "CWE-89":   "SQL Injection",
    "CWE-94":   "Code Injection",
    "CWE-119":  "Buffer Overflow",
    "CWE-120":  "Buffer Copy without Size Check",
    "CWE-121":  "Stack Buffer Overflow",
    "CWE-122":  "Heap Buffer Overflow",
    "CWE-125":  "Out-of-bounds Read",
    "CWE-190":  "Integer Overflow",
    "CWE-200":  "Information Disclosure",
    "CWE-203":  "Observable Discrepancy",
    "CWE-209":  "Information Exposure Through Error Message",
    "CWE-269":  "Improper Privilege Management",
    "CWE-275":  "Permission Issues",
    "CWE-284":  "Improper Access Control",
    "CWE-287":  "Improper Authentication",
    "CWE-288":  "Authentication Bypass",
    "CWE-290":  "Authentication Bypass by Spoofing",
    "CWE-294":  "Authentication Bypass by Capture-replay",
    "CWE-295":  "Improper Certificate Validation",
    "CWE-306":  "Missing Authentication",
    "CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311":  "Missing Encryption",
    "CWE-319":  "Cleartext Transmission",
    "CWE-326":  "Inadequate Encryption Strength",
    "CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-331":  "Insufficient Entropy",
    "CWE-345":  "Insufficient Verification of Data Authenticity",
    "CWE-352":  "Cross-Site Request Forgery",
    "CWE-362":  "Race Condition",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-401":  "Missing Release of Memory",
    "CWE-415":  "Double Free",
    "CWE-416":  "Use After Free",
    "CWE-426":  "Untrusted Search Path",
    "CWE-427":  "Uncontrolled Search Path Element",
    "CWE-434":  "Unrestricted File Upload",
    "CWE-441":  "Unintended Proxy or Intermediary",
    "CWE-476":  "NULL Pointer Dereference",
    "CWE-502":  "Deserialization of Untrusted Data",
    "CWE-521":  "Weak Password Requirements",
    "CWE-522":  "Insufficiently Protected Credentials",
    "CWE-532":  "Information Exposure Through Log Files",
    "CWE-552":  "Files or Directories Accessible to External Parties",
    "CWE-601":  "Open Redirect",
    "CWE-611":  "XML External Entity (XXE)",
    "CWE-639":  "Authorization Bypass Through User-Controlled Key",
    "CWE-668":  "Exposure of Resource to Wrong Sphere",
    "CWE-732":  "Incorrect Permission Assignment",
    "CWE-770":  "Allocation of Resources Without Limits",
    "CWE-787":  "Out-of-bounds Write",
    "CWE-798":  "Hard-coded Credentials",
    "CWE-862":  "Missing Authorization",
    "CWE-863":  "Incorrect Authorization",
    "CWE-915":  "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918":  "Server-Side Request Forgery (SSRF)",
    "CWE-1188": "Insecure Default Initialization",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-1321": "Prototype Pollution",
}


def lookup(cwe_id: str) -> str | None:
    """Return the short human name for a CWE ID, or None if not in the table."""
    return CWE_NAMES.get(cwe_id)
