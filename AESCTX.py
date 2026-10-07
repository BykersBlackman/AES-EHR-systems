import os
import time
import json
import logging
import secrets
import sys
import unittest
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort # type: ignore
from jinja2 import DictLoader # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # type: ignore
from synthetic_data import build_dataset, CLINICAL_DEPARTMENTS # type: ignore

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)

# -----------------------------------------------------------------------------
# Global Configuration
# -----------------------------------------------------------------------------
# Roles and departments come from the shared data module so the whole system
# (app, evaluation and CSV extracts) stays consistent.
ROLES = ["doctor", "nurse", "admin"]
DEPARTMENTS = CLINICAL_DEPARTMENTS  # clinical departments shown in the UI

# -----------------------------------------------------------------------------
# AES Key Management System (Role-Based)
# -----------------------------------------------------------------------------
class AESKeyManager:
    """
    Manages AES keys on a per-role basis.
    """
    def __init__(self):
        # Keys stored as: { role: (key, timestamp) }
        self.keys = {}

    def generate_key(self):
        """Generate a new 256-bit AES key."""
        return os.urandom(32)

    def add_role_key(self, role):
        """Generate and store an AES key for a role."""
        key = self.generate_key()
        self.keys[role] = (key, time.time())
        logging.info(f"[KMS] Key generated for role '{role}' at {time.ctime()}.")

    def rotate_key(self, role):
        """Rotate the AES key for a role."""
        if role in self.keys:
            new_key = self.generate_key()
            self.keys[role] = (new_key, time.time())
            logging.info(f"[KMS] Key rotated for role '{role}' at {time.ctime()}.")
        else:
            logging.warning(f"[KMS] No key found for role '{role}'.")

    def get_key(self, role):
        """Retrieve the AES key for the specified role."""
        return self.keys.get(role, (None, None))[0]

# Initialize key manager and generate keys for each role.
key_manager = AESKeyManager()
for role in ROLES:
    key_manager.add_role_key(role)

# -----------------------------------------------------------------------------
# Synthetic Data (correlated staff, patients and EHR records)
# -----------------------------------------------------------------------------
# build_dataset() returns a referentially consistent dataset: staff accounts,
# a patient master, and per-role EHR records where every clinical record belongs
# to a real patient and is written by that patient's attending clinician.
# Doctor and nurse records share ehr_id numbering (each encounter yields one of
# each), so an ehr_id is unique only within a role.
staff_members, patients, synthetic_records = build_dataset()

# Pre-encrypt the synthetic records for each role (store by role and ehr_id).
encrypted_records = {role: {} for role in ROLES}

def encrypt_record(record, key):
    """
    Encrypt a record (as JSON) using AES-GCM.
    Returns a dictionary with ciphertext, nonce, and key_id.
    """
    plaintext = json.dumps(record).encode('utf-8')
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM.
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"ciphertext": ciphertext, "nonce": nonce, "key_id": record["key_id"]}

def decrypt_record(encrypted_record, key):
    """
    Decrypt an AES-GCM encrypted record.
    Returns the original record as a dictionary.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(encrypted_record["nonce"], encrypted_record["ciphertext"], None)
    return json.loads(plaintext.decode('utf-8'))

# Encrypt and store records for each role.
for role, records in synthetic_records.items():
    key = key_manager.get_key(role)
    for record in records:
        encrypted_records[role][record["ehr_id"]] = encrypt_record(record, key)

# -----------------------------------------------------------------------------
# Context-Aware Policy Engine with Extended Validations
# -----------------------------------------------------------------------------
class ContextAwareEngine:
    """
    Evaluates whether a user is allowed to access a particular record based on:
        - Role: The user's role must match the record's assigned role.
        - Department: The user's department must match the record's department.
        - Grade: The user's grade (experience level) must be equal to or exceed the record's minimum required grade.
    """
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def evaluate_access(self, user, record):
        """
        Validates access based on:
            - user['role'] equals record['assigned_role']
            - user['department'] equals record['department']
            - user['grade'] >= record['min_grade']
        Returns:
            The AES key if all validations pass, otherwise None.
        """
        if user['role'] != record['assigned_role']:
            logging.warning(f"[Policy] Access denied. User role '{user['role']}' does not match record role '{record['assigned_role']}'.")
            return None
        if user.get('department') != record.get('department'):
            logging.warning(f"[Policy] Access denied. User department '{user.get('department')}' does not match record department '{record.get('department')}'.")
            return None
        if int(user.get('grade', 0)) < int(record.get('min_grade', 0)):
            logging.warning(f"[Policy] Access denied. User grade '{user.get('grade')}' is lower than record minimum grade '{record.get('min_grade')}'.")
            return None
        # If all conditions pass, retrieve and return the AES key for that role.
        return self.key_manager.get_key(user['role'])

# Initialize extended policy engine.
policy_engine = ContextAwareEngine(key_manager)

# -----------------------------------------------------------------------------
# User Interface: Design Tokens, Layouts and Page Templates
# -----------------------------------------------------------------------------
# All pages share one stylesheet and two layouts (auth + app shell). Templates are
# served from memory through a Jinja DictLoader so they can extend each other.

STYLES = """
:root {
  --bg: #f3f5f4; --surface: #ffffff; --surface-sunken: #eef2f1;
  --line: #d8dfdd; --line-strong: #869490;
  --ink: #0f1d1b; --ink-muted: #4f5f5b; --ink-faint: #5f6e6a;
  --brand: #0f5c57; --brand-hover: #0b4945; --brand-soft: #e2efed; --on-brand: #ffffff;
  --danger: #a3261b; --danger-soft: #fbeae7;
  --warning: #7a4a00; --warning-soft: #fdf2dc;
  --success: #1c6a39; --success-soft: #e5f2e9;
  --info: #1d4e79; --info-soft: #e5edf6;
  --focus: #0f5c57;
  --shadow-sm: 0 1px 2px rgba(15, 29, 27, .06);
  --shadow-md: 0 1px 2px rgba(15, 29, 27, .04), 0 12px 32px rgba(15, 29, 27, .07);
  --radius-sm: 6px; --radius-md: 10px; --radius-lg: 16px;
  --font-sans: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --font-mono: "IBM Plex Mono", ui-monospace, Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0c1312; --surface: #131c1b; --surface-sunken: #182321;
    --line: #26322f; --line-strong: #647470;
    --ink: #e4ecea; --ink-muted: #a3b1ad; --ink-faint: #85948f;
    --brand: #5cc2b5; --brand-hover: #7fd3c8; --brand-soft: #14302c; --on-brand: #04201d;
    --danger: #ff9b8d; --danger-soft: #3a1714;
    --warning: #f2c063; --warning-soft: #33260c;
    --success: #7dd49a; --success-soft: #11291a;
    --info: #8ebcf0; --info-soft: #132438;
    --focus: #5cc2b5;
    --shadow-sm: 0 1px 2px rgba(0, 0, 0, .4);
    --shadow-md: 0 1px 2px rgba(0, 0, 0, .3), 0 12px 32px rgba(0, 0, 0, .35);
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #0c1312; --surface: #131c1b; --surface-sunken: #182321;
  --line: #26322f; --line-strong: #647470;
  --ink: #e4ecea; --ink-muted: #a3b1ad; --ink-faint: #85948f;
  --brand: #5cc2b5; --brand-hover: #7fd3c8; --brand-soft: #14302c; --on-brand: #04201d;
  --danger: #ff9b8d; --danger-soft: #3a1714;
  --warning: #f2c063; --warning-soft: #33260c;
  --success: #7dd49a; --success-soft: #11291a;
  --info: #8ebcf0; --info-soft: #132438;
  --focus: #5cc2b5;
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, .4);
  --shadow-md: 0 1px 2px rgba(0, 0, 0, .3), 0 12px 32px rgba(0, 0, 0, .35);
  color-scheme: dark;
}

*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; }
body {
  background: var(--bg); color: var(--ink);
  font-family: var(--font-sans); font-size: 15px; line-height: 1.55;
  -webkit-font-smoothing: antialiased; min-height: 100vh;
}
a { color: var(--brand); text-decoration: none; }
a:hover { color: var(--brand-hover); }
h1, h2, h3 { margin: 0; letter-spacing: -0.015em; line-height: 1.2; }
h1 { font-size: 28px; font-weight: 600; }
h2 { font-size: 18px; font-weight: 600; }
p { margin: 0; }
.mono { font-family: var(--font-mono); font-size: .92em; letter-spacing: -0.01em; }
.muted { color: var(--ink-muted); }
.eyebrow {
  font-size: 12px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--ink-faint);
}
.icon { width: 18px; height: 18px; flex: none; stroke: currentColor; fill: none; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

/* Buttons ---------------------------------------------------------------- */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  height: 40px; padding: 0 16px; border-radius: var(--radius-md);
  font: 500 14px/1 var(--font-sans); cursor: pointer; white-space: nowrap;
  border: 1px solid transparent; transition: background .15s, border-color .15s, color .15s;
}
.btn-primary { background: var(--brand); color: var(--on-brand); }
.btn-primary:hover { background: var(--brand-hover); color: var(--on-brand); }
.btn-secondary { background: var(--surface); color: var(--ink); border-color: var(--line-strong); }
.btn-secondary:hover { background: var(--surface-sunken); color: var(--ink); }
.btn-ghost { background: transparent; color: var(--ink-muted); }
.btn-ghost:hover { background: var(--surface-sunken); color: var(--ink); }
.btn-caution { background: var(--warning-soft); color: var(--warning); border-color: var(--warning); }
.btn-caution:hover { filter: brightness(0.97); color: var(--warning); }
.btn-sm { height: 32px; padding: 0 12px; font-size: 13px; border-radius: var(--radius-sm); }
.btn-block { width: 100%; }
.btn-icon { width: 40px; padding: 0; }

/* Forms ------------------------------------------------------------------ */
.field { display: grid; gap: 6px; margin-bottom: 16px; }
.field label { font-size: 13px; font-weight: 500; color: var(--ink); }
.field .hint { font-size: 12.5px; color: var(--ink-muted); }
.input, .select {
  width: 100%; height: 44px; padding: 0 14px; border-radius: var(--radius-md);
  border: 1px solid var(--line-strong); background: var(--surface); color: var(--ink);
  font: 400 15px var(--font-sans); transition: border-color .15s, box-shadow .15s;
}
.input::placeholder { color: var(--ink-faint); }
.input:focus, .select:focus { outline: none; border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-soft); }
.input.code { font-family: var(--font-mono); letter-spacing: .3em; font-size: 18px; text-align: center; text-transform: lowercase; }
.input.hash { font-family: var(--font-mono); font-size: 14px; letter-spacing: .02em; }
.select { appearance: none; padding-right: 36px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b7a76' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 14px center; }

/* Cards, alerts, badges ---------------------------------------------------- */
.card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius-lg); box-shadow: var(--shadow-sm); }
.card-pad { padding: 24px; }
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 18px 24px; border-bottom: 1px solid var(--line); }

.alerts { display: grid; gap: 10px; margin-bottom: 20px; }
.alert {
  display: flex; gap: 10px; align-items: flex-start; padding: 12px 14px;
  border-radius: var(--radius-md); border: 1px solid; font-size: 14px; font-weight: 500;
}
.alert .icon { margin-top: 1px; }
.alert-error   { background: var(--danger-soft);  color: var(--danger);  border-color: var(--danger); }
.alert-warning { background: var(--warning-soft); color: var(--warning); border-color: var(--warning); }
.alert-success { background: var(--success-soft); color: var(--success); border-color: var(--success); }
.alert-info    { background: var(--info-soft);    color: var(--info);    border-color: var(--info); }

.badge {
  display: inline-flex; align-items: center; gap: 6px; height: 24px; padding: 0 10px;
  border-radius: 999px; font-size: 12px; font-weight: 500; white-space: nowrap;
  background: var(--surface-sunken); color: var(--ink-muted); border: 1px solid var(--line);
}
.badge .icon { width: 13px; height: 13px; }
.badge-brand { background: var(--brand-soft); color: var(--brand); border-color: transparent; }
.badge-ok { background: var(--success-soft); color: var(--success); border-color: transparent; }
.badge-locked { background: var(--surface-sunken); color: var(--ink-muted); }

.grade { display: inline-flex; gap: 3px; align-items: center; }
.grade i { width: 8px; height: 8px; border-radius: 2px; background: var(--line); }
.grade i.on { background: var(--brand); }
.grade span { margin-left: 6px; font-size: 13px; color: var(--ink-muted); font-variant-numeric: tabular-nums; }

/* Auth layout ------------------------------------------------------------ */
.auth { display: grid; grid-template-columns: minmax(320px, 440px) 1fr; min-height: 100vh; }
.auth-aside {
  background: #0d2523; color: #dbe9e6; padding: 40px; display: flex; flex-direction: column; justify-content: space-between; gap: 40px;
  position: relative; overflow: hidden;
}
.auth-aside::after {
  content: ""; position: absolute; inset: auto -120px -120px auto; width: 360px; height: 360px; border-radius: 50%;
  border: 1px solid rgba(219, 233, 230, .12); box-shadow: 0 0 0 48px rgba(219, 233, 230, .03), 0 0 0 96px rgba(219, 233, 230, .025);
}
.auth-aside .brand { color: #ffffff; }
.auth-aside .brand-mark { background: #5cc2b5; color: #04201d; }
.auth-aside h2 { font-size: 26px; font-weight: 500; color: #ffffff; max-width: 320px; letter-spacing: -0.02em; }
.auth-aside p { color: #a9c1bc; margin-top: 12px; max-width: 340px; }
.flow { list-style: none; padding: 0; margin: 0; display: grid; gap: 4px; position: relative; z-index: 1; }
.flow li { display: flex; gap: 14px; align-items: center; padding: 10px 0; color: #a9c1bc; font-size: 14px; }
.flow li b { color: #ffffff; font-weight: 500; display: block; }
.flow .num {
  width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; flex: none;
  border: 1px solid rgba(219, 233, 230, .25); font: 500 12px var(--font-mono); color: #dbe9e6;
}
.flow li.active .num { background: #5cc2b5; color: #04201d; border-color: #5cc2b5; }
.flow li.done .num { background: rgba(92, 194, 181, .16); color: #5cc2b5; border-color: transparent; }
.auth-aside small { color: #7f9c96; font-size: 12px; position: relative; z-index: 1; }
.auth-main { display: flex; flex-direction: column; padding: 24px 40px; }
.auth-main .tools { display: flex; justify-content: flex-end; }
.auth-panel { width: 100%; max-width: 440px; margin: auto; padding: 32px 0; }
.auth-panel header { margin-bottom: 28px; }
.auth-panel header p { margin-top: 8px; color: var(--ink-muted); }

.brand { display: inline-flex; align-items: center; gap: 10px; font-weight: 600; font-size: 16px; color: var(--ink); letter-spacing: -0.01em; }
.brand-mark { width: 32px; height: 32px; border-radius: 9px; display: grid; place-items: center; background: var(--brand); color: var(--on-brand); }
.brand-mark .icon { width: 18px; height: 18px; }

.role-options { display: grid; gap: 10px; margin-bottom: 20px; }
.role-option { position: relative; }
.role-option input { position: absolute; opacity: 0; pointer-events: none; }
.role-option label {
  display: flex; align-items: center; gap: 14px; padding: 14px 16px; cursor: pointer;
  border: 1px solid var(--line-strong); border-radius: var(--radius-md); background: var(--surface);
  transition: border-color .15s, background .15s, box-shadow .15s;
}
.role-option label:hover { border-color: var(--ink-faint); }
.role-option .ri { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; background: var(--surface-sunken); color: var(--ink-muted); flex: none; }
.role-option strong { display: block; font-weight: 500; }
.role-option small { color: var(--ink-muted); font-size: 13px; }
.role-option .check { margin-left: auto; width: 18px; height: 18px; border-radius: 50%; border: 1.5px solid var(--line-strong); flex: none; }
.role-option input:checked + label { border-color: var(--brand); background: var(--brand-soft); box-shadow: 0 0 0 1px var(--brand); }
.role-option input:checked + label .ri { background: var(--brand); color: var(--on-brand); }
.role-option input:checked + label .check { border: 5px solid var(--brand); }
.role-option input:focus-visible + label { outline: 2px solid var(--focus); outline-offset: 2px; }

.step { border: 1px solid var(--line); border-radius: var(--radius-lg); background: var(--surface); padding: 20px; margin-bottom: 14px; box-shadow: var(--shadow-sm); }
.step-head { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
.step-head .num { width: 24px; height: 24px; border-radius: 50%; display: grid; place-items: center; background: var(--surface-sunken); color: var(--ink-muted); font: 500 12px var(--font-mono); }
.step.current .step-head .num { background: var(--brand); color: var(--on-brand); }
.step-head h2 { font-size: 15px; }
.back-link { display: inline-flex; align-items: center; gap: 6px; font-size: 13.5px; color: var(--ink-muted); margin-top: 8px; }
.back-link:hover { color: var(--ink); }

/* App shell -------------------------------------------------------------- */
.topbar {
  position: sticky; top: 0; z-index: 10; height: 64px; padding: 0 32px;
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  background: color-mix(in srgb, var(--surface) 88%, transparent); backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--line);
}
.topbar-right { display: flex; align-items: center; gap: 8px; }
.user-chip { display: flex; align-items: center; gap: 10px; padding: 4px 12px 4px 4px; border-radius: 999px; border: 1px solid var(--line); }
.avatar { width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; background: var(--brand-soft); color: var(--brand); font-weight: 600; font-size: 13px; }
.user-chip .who { line-height: 1.2; }
.user-chip .who b { display: block; font-size: 13px; font-weight: 500; }
.user-chip .who small { font-size: 12px; color: var(--ink-muted); }
.page { max-width: 1240px; margin: 0 auto; padding: 32px; }
.page-narrow { max-width: 560px; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
.page-head p { margin-top: 6px; color: var(--ink-muted); }

.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 24px; }
.stat { padding: 18px 20px; }
.stat .value { font-size: 26px; font-weight: 600; letter-spacing: -0.02em; margin-top: 6px; font-variant-numeric: tabular-nums; }
.stat .value.text { font-size: 18px; padding-top: 6px; }
.stat .sub { font-size: 12.5px; color: var(--ink-muted); margin-top: 2px; }

.layout { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 20px; align-items: start; }
.layout.single { grid-template-columns: minmax(0, 1fr); }

.toolbar { display: flex; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line); flex-wrap: wrap; align-items: center; }
.search { position: relative; flex: 1 1 240px; }
.search .icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--ink-faint); width: 16px; height: 16px; }
.search .input { height: 38px; padding-left: 36px; font-size: 14px; }
.toolbar .select { height: 38px; width: auto; min-width: 170px; font-size: 14px; }
.toolbar .count { font-size: 13px; color: var(--ink-muted); margin-left: auto; font-variant-numeric: tabular-nums; }

.table-wrap { overflow: auto; max-height: 640px; }
table.data { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 14px; }
table.data th {
  position: sticky; top: 0; background: var(--surface-sunken); text-align: left; font-weight: 500;
  font-size: 12px; letter-spacing: .04em; text-transform: uppercase; color: var(--ink-muted);
  padding: 0; border-bottom: 1px solid var(--line); white-space: nowrap;
}
table.data th button {
  all: unset; display: inline-flex; align-items: center; gap: 4px; padding: 10px 12px; cursor: pointer; width: 100%; box-sizing: border-box;
}
table.data th button:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
table.data th .arrow { opacity: .35; font-size: 10px; }
table.data th[aria-sort] .arrow { opacity: 1; color: var(--brand); }
table.data th.plain { padding: 10px 12px; }
table.data td { padding: 12px 12px; border-bottom: 1px solid var(--line); vertical-align: middle; white-space: nowrap; }
table.data tbody tr:hover td { background: var(--surface-sunken); }
table.data td.num { color: var(--ink-faint); font-variant-numeric: tabular-nums; }
table.data td.act { text-align: right; }
.empty { padding: 48px 16px; text-align: center; color: var(--ink-muted); }

.side { display: grid; gap: 20px; }
.key-list { list-style: none; margin: 0; padding: 0; }
.key-list li { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px dashed var(--line); }
.key-list li:last-child { border-bottom: 0; }
.key-list b { font-weight: 500; font-size: 14px; display: block; }
.key-list small { font-size: 12px; color: var(--ink-muted); }
.policy { list-style: none; margin: 0; padding: 0; display: grid; gap: 12px; font-size: 14px; }
.policy li { display: flex; gap: 10px; color: var(--ink-muted); }
.policy li .icon { color: var(--brand); width: 16px; height: 16px; margin-top: 3px; }
.policy b { color: var(--ink); font-weight: 500; }

/* Record ----------------------------------------------------------------- */
.record-head { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; padding: 24px; border-bottom: 1px solid var(--line); }
.record-head h1 { font-family: var(--font-mono); font-size: 24px; font-weight: 500; letter-spacing: -0.02em; margin-top: 6px; }
.record-head .badges { display: flex; gap: 8px; flex-wrap: wrap; }
.kv { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-bottom: 1px solid var(--line); }
.kv div { padding: 18px 24px; border-right: 1px solid var(--line); }
.kv div:last-child { border-right: 0; }
.kv dt { font-size: 12px; color: var(--ink-faint); text-transform: uppercase; letter-spacing: .06em; font-weight: 500; }
.kv dd { margin: 6px 0 0; font-weight: 500; }
.notes { display: grid; grid-template-columns: 1fr 1fr; }
.notes section { padding: 24px; }
.notes section + section { border-left: 1px solid var(--line); }
.notes h2 { font-size: 13px; font-weight: 500; color: var(--ink-faint); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 10px; }
.notes p { font-size: 16px; line-height: 1.6; }
.record-foot { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 16px 24px; background: var(--surface-sunken); border-radius: 0 0 var(--radius-lg) var(--radius-lg); font-size: 13px; color: var(--ink-muted); flex-wrap: wrap; }

.denied { text-align: center; padding: 48px 24px; }
.denied .ring { width: 56px; height: 56px; border-radius: 50%; margin: 0 auto 16px; display: grid; place-items: center; background: var(--danger-soft); color: var(--danger); }

/* Responsive ------------------------------------------------------------- */
@media (max-width: 1024px) {
  .layout { grid-template-columns: minmax(0, 1fr); }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 820px) {
  .auth { grid-template-columns: 1fr; }
  .auth-aside { padding: 24px 16px; gap: 20px; }
  .auth-aside .flow, .auth-aside small, .auth-aside::after { display: none; }
  .auth-aside h2 { font-size: 20px; }
  .auth-main { padding: 16px; }
  .topbar { padding: 0 16px; }
  .user-chip .who { display: none; }
  .user-chip { padding: 2px; }
  .page { padding: 20px 16px; }
  .kv { grid-template-columns: 1fr 1fr; }
  .kv div:nth-child(2n) { border-right: 0; }
  .kv div:nth-child(-n+2) { border-bottom: 1px solid var(--line); }
  .notes { grid-template-columns: 1fr; }
  .notes section + section { border-left: 0; border-top: 1px solid var(--line); }
}
"""

# Inline SVG icons (stroke-based, 24px grid) used throughout the templates.
ICONS = """
{% macro icon(name) -%}
<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
{%- if name == 'shield' -%}<path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3Z"/><path d="m9 12 2 2 4-4"/>
{%- elif name == 'stethoscope' -%}<path d="M6 3v5a4 4 0 0 0 8 0V3"/><path d="M10 12v2a5 5 0 0 0 10 0v-1"/><circle cx="20" cy="11" r="2"/>
{%- elif name == 'heart' -%}<path d="M12 20s-7.5-4.4-7.5-10A4.3 4.3 0 0 1 12 7.4 4.3 4.3 0 0 1 19.5 10c0 5.6-7.5 10-7.5 10Z"/><path d="M8 12h2l1-2 2 4 1-2h2"/>
{%- elif name == 'settings' -%}<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/>
{%- elif name == 'lock' -%}<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>
{%- elif name == 'unlock' -%}<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/>
{%- elif name == 'key' -%}<circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M17 6l3 3M14.5 8.5l2 2"/>
{%- elif name == 'mail' -%}<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>
{%- elif name == 'logout' -%}<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 17l-5-5 5-5M5 12h11"/>
{%- elif name == 'search' -%}<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>
{%- elif name == 'arrow-left' -%}<path d="M19 12H5M11 18l-6-6 6-6"/>
{%- elif name == 'arrow-right' -%}<path d="M5 12h14M13 6l6 6-6 6"/>
{%- elif name == 'alert' -%}<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5v.01"/>
{%- elif name == 'check' -%}<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>
{%- elif name == 'info' -%}<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5M12 7.5v.01"/>
{%- elif name == 'theme' -%}<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17a8.5 8.5 0 0 0 0-17Z" fill="currentColor"/>
{%- elif name == 'refresh' -%}<path d="M20 11a8 8 0 0 0-14.6-4.5L3 9"/><path d="M3 4v5h5M4 13a8 8 0 0 0 14.6 4.5L21 15"/><path d="M21 20v-5h-5"/>
{%- endif -%}
</svg>
{%- endmacro %}
"""

TEMPLATES = {
    "styles.css": STYLES,
    "icons.html": ICONS,

    # ------------------------------------------------------------------ base
    "base.html": """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}SecureEHR{% endblock %}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
  <script>try { var t = localStorage.getItem('ehr-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) {}</script>
  <style>{% include "styles.css" %}</style>
</head>
<body>
{% block body %}{% endblock %}
<script>
  function toggleTheme() {
    var root = document.documentElement;
    var current = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    var next = current === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    try { localStorage.setItem('ehr-theme', next); } catch (e) {}
  }
</script>
{% block scripts %}{% endblock %}
</body>
</html>""",

    "flashes.html": """{% from "icons.html" import icon %}
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
  <div class="alerts" role="status" aria-live="polite">
    {% for category, message in messages %}
      {% set kind = category if category in ['error', 'warning', 'success', 'info'] else 'info' %}
      <div class="alert alert-{{ kind }}">
        {{ icon({'error': 'alert', 'warning': 'alert', 'success': 'check', 'info': 'info'}[kind]) }}
        <div>{{ message }}</div>
      </div>
    {% endfor %}
  </div>
  {% endif %}
{% endwith %}""",

    # ----------------------------------------------------------- auth layout
    "auth_layout.html": """{% extends "base.html" %}
{% from "icons.html" import icon %}
{% block body %}
<div class="auth">
  <aside class="auth-aside">
    <div class="brand"><span class="brand-mark">{{ icon('shield') }}</span>SecureEHR</div>
    <div>
      <h2>Encrypted health records, unlocked only in context.</h2>
      <p>Every record is sealed with a role-bound AES-256-GCM key and released only when role, department and clearance grade all match.</p>
    </div>
    <ol class="flow">
      {% set steps = [('Select your role', 'Doctor, nurse or administrator'),
                      ('Verify with a one-time code', 'Sent to your registered email'),
                      ('Confirm the patient hash', 'Second factor per record'),
                      ('Record decrypted', 'Policy-checked, then AES-GCM')] %}
      {% for title, sub in steps %}
      <li class="{{ 'active' if loop.index == step else ('done' if loop.index < step else '') }}">
        <span class="num">{{ loop.index }}</span>
        <span><b>{{ title }}</b>{{ sub }}</span>
      </li>
      {% endfor %}
    </ol>
    <small>Research prototype · synthetic patient data only</small>
  </aside>
  <main class="auth-main">
    <div class="tools">
      <button class="btn btn-ghost btn-icon" type="button" onclick="toggleTheme()" aria-label="Toggle light or dark theme">{{ icon('theme') }}</button>
    </div>
    <div class="auth-panel">
      {% include "flashes.html" %}
      {% block panel %}{% endblock %}
    </div>
  </main>
</div>
{% endblock %}""",

    # ------------------------------------------------------------ app layout
    "app_layout.html": """{% extends "base.html" %}
{% from "icons.html" import icon %}
{% block body %}
{% set me = session.get('staff') %}
<header class="topbar">
  <a class="brand" href="{{ url_for('dashboard') }}"><span class="brand-mark">{{ icon('shield') }}</span>SecureEHR</a>
  <div class="topbar-right">
    <button class="btn btn-ghost btn-icon" type="button" onclick="toggleTheme()" aria-label="Toggle light or dark theme">{{ icon('theme') }}</button>
    {% if me %}
    <div class="user-chip">
      <span class="avatar">{{ me.name[:1] }}</span>
      <span class="who"><b>{{ me.name }}</b><small>{{ me.role.capitalize() }} · {{ me.department }}</small></span>
    </div>
    <a class="btn btn-ghost" href="{{ url_for('logout') }}">{{ icon('logout') }}<span>Logout</span></a>
    {% endif %}
  </div>
</header>
<main class="page {% block page_class %}{% endblock %}">
  {% include "flashes.html" %}
  {% block content %}{% endblock %}
</main>
{% endblock %}""",

    # ------------------------------------------------------------------ home
    "home.html": """{% extends "auth_layout.html" %}
{% block title %}SecureEHR · Select Your Role{% endblock %}
{% block panel %}
<header>
  <p class="eyebrow">Step 1 of 4</p>
  <h1 style="margin-top:8px">Select Your Role to Login</h1>
  <p>Your role determines which encryption key and record set you can reach.</p>
</header>
<form method="get" action="{{ url_for('select_role') }}">
  {% set role_meta = {'doctor': ('stethoscope', 'Diagnosis and treatment records'),
                      'nurse': ('heart', 'Care and ward records'),
                      'admin': ('settings', 'Administration and key management')} %}
  <fieldset class="role-options" style="border:0;padding:0;margin:0 0 20px">
    <legend class="eyebrow" style="margin-bottom:10px">Role</legend>
    {% for r in roles %}
    <div class="role-option">
      <input type="radio" name="role" id="role-{{ r }}" value="{{ r }}" {{ 'checked' if loop.first }} required>
      <label for="role-{{ r }}">
        <span class="ri">{{ icon(role_meta[r][0]) }}</span>
        <span><strong>{{ r.capitalize() }}</strong><small>{{ role_meta[r][1] }}</small></span>
        <span class="check" aria-hidden="true"></span>
      </label>
    </div>
    {% endfor %}
  </fieldset>
  <button type="submit" class="btn btn-primary btn-block">Proceed {{ icon('arrow-right') }}</button>
</form>
{% endblock %}""",

    # ----------------------------------------------------------------- login
    "login.html": """{% extends "auth_layout.html" %}
{% block title %}SecureEHR · {{ role.capitalize() }} Login{% endblock %}
{% block panel %}
{% set pending_id = session.get('otp_staff_id') if session.get('otp_role') == role else '' %}
<header>
  <p class="eyebrow">Step 2 of 4</p>
  <h1 style="margin-top:8px">Login for {{ role.capitalize() }}</h1>
  <p>Enter your Staff ID and request an OTP.</p>
</header>

<section class="step {{ '' if pending_id else 'current' }}">
  <div class="step-head"><span class="num">1</span><h2>Request a one-time code</h2></div>
  <form method="post" action="{{ url_for('request_otp', role=role) }}">
    <div class="field">
      <label for="otp_staff_id">Staff ID</label>
      <input type="text" class="input mono" id="otp_staff_id" name="staff_id" placeholder="e.g. {{ {'doctor': 'DOC001', 'nurse': 'NUR001', 'admin': 'ADM001'}[role] }}" value="{{ pending_id }}" autocomplete="username" required>
    </div>
    <button type="submit" class="btn btn-secondary btn-block">{{ icon('mail') }} {{ 'Resend OTP' if pending_id else 'Request OTP' }}</button>
  </form>
</section>

<section class="step {{ 'current' if pending_id else '' }}">
  <div class="step-head"><span class="num">2</span><h2>Enter the code</h2></div>
  <form method="post" action="{{ url_for('login_role', role=role) }}">
    <div class="field">
      <label for="login_staff_id">Staff ID</label>
      <input type="text" class="input mono" id="login_staff_id" name="staff_id" placeholder="Enter your Staff ID" value="{{ pending_id }}" autocomplete="username" required>
    </div>
    <div class="field">
      <label for="otp">One-time code</label>
      <input type="text" class="input code" id="otp" name="otp" placeholder="······" maxlength="6" autocomplete="one-time-code" spellcheck="false" required {{ 'autofocus' if pending_id }}>
      <span class="hint">Six characters, sent to the email registered to your Staff ID.</span>
    </div>
    <button type="submit" class="btn btn-primary btn-block">{{ icon('lock') }} Login</button>
  </form>
</section>
<a class="back-link" href="{{ url_for('home') }}">{{ icon('arrow-left') }} Choose a different role</a>
{% endblock %}""",

    # ------------------------------------------------------------- dashboard
    "dashboard.html": """{% extends "app_layout.html" %}
{% block title %}SecureEHR · {{ staff.role.capitalize() }} Dashboard{% endblock %}
{% block content %}
{% set ns = namespace(eligible=0) %}
{% for rec in records %}{% if rec.assigned_role == staff.role and rec.department == staff.department and staff.grade >= rec.min_grade %}{% set ns.eligible = ns.eligible + 1 %}{% endif %}{% endfor %}

<div class="page-head">
  <div>
    <p class="eyebrow">{{ staff.role.capitalize() }} Dashboard</p>
    <h1 style="margin-top:6px">Welcome, {{ staff.name }}</h1>
    <p>
      {% if staff.grade == 5 %}
        You have level 5 access. Viewing all records across all departments.
      {% else %}
        Viewing records for your department: <strong>{{ staff.department }}</strong>.
      {% endif %}
    </p>
  </div>
  <span class="badge badge-brand">{{ icon('key') }} AES-256-GCM · {{ staff.role.upper() }}_AES256</span>
</div>

<div class="stats">
  <div class="card stat"><div class="eyebrow">Records in view</div><div class="value">{{ records|length }}</div><div class="sub">{{ 'All departments' if staff.grade == 5 else staff.department }}</div></div>
  <div class="card stat"><div class="eyebrow">Eligible to open</div><div class="value">{{ ns.eligible }}</div><div class="sub">Role, department and grade match</div></div>
  <div class="card stat"><div class="eyebrow">Department</div><div class="value text">{{ staff.department }}</div><div class="sub">{{ staff.role.capitalize() }} · {{ staff.id }}</div></div>
  <div class="card stat"><div class="eyebrow">Clearance grade</div><div class="value">{{ staff.grade }}<span class="muted" style="font-size:16px;font-weight:400"> / 5</span></div>
    <div class="sub"><span class="grade" aria-hidden="true">{% for i in range(1, 6) %}<i class="{{ 'on' if i <= staff.grade }}"></i>{% endfor %}</span></div></div>
</div>

<div class="layout {{ '' if staff.role == 'admin' else 'single' }}">
  <section class="card" aria-label="Patient records">
    <div class="toolbar">
      <label class="search">{{ icon('search') }}<input class="input" type="search" id="q" placeholder="Search patient name, ID, EHR ID or department" aria-label="Search records"></label>
      <select class="select" id="dept" aria-label="Filter by department">
        <option value="">All departments</option>
        {% for d in records|map(attribute='department')|unique|sort %}<option>{{ d }}</option>{% endfor %}
      </select>
      <select class="select" id="access" aria-label="Filter by access">
        <option value="">All access levels</option>
        <option value="eligible">Eligible only</option>
        <option value="restricted">Restricted only</option>
      </select>
      <span class="count" id="count">{{ records|length }} records</span>
    </div>
    <div class="table-wrap">
      <table class="data" id="records">
        <thead>
          <tr>
            <th data-key="ehr" data-type="num"><button type="button">EHR ID <span class="arrow">▲▼</span></button></th>
            <th data-key="name"><button type="button">Patient <span class="arrow">▲▼</span></button></th>
            <th data-key="role"><button type="button">Role <span class="arrow">▲▼</span></button></th>
            <th data-key="dept"><button type="button">Department <span class="arrow">▲▼</span></button></th>
            <th data-key="grade" data-type="num" title="Min Grade Required"><button type="button">Min Grade <span class="arrow">▲▼</span></button></th>
            <th class="plain">Access</th>
            <th class="plain"><span class="sr-only" style="position:absolute;left:-9999px">Action</span></th>
          </tr>
        </thead>
        <tbody>
        {% for rec in records %}
          {% set ok = rec.assigned_role == staff.role and rec.department == staff.department and staff.grade >= rec.min_grade %}
          {% set display_name = rec.patient_name or rec.subject_name or rec.patient_id %}
          <tr data-ehr="{{ rec.ehr_id }}" data-pid="{{ rec.patient_id }}" data-name="{{ display_name }}" data-role="{{ rec.assigned_role }}" data-dept="{{ rec.department }}" data-grade="{{ rec.min_grade }}" data-access="{{ 'eligible' if ok else 'restricted' }}">
            <td class="num mono">{{ '%03d' % rec.ehr_id }}</td>
            <td><div style="font-weight:500">{{ display_name }}</div><div class="mono" style="font-size:12px;color:var(--ink-faint)">{{ rec.patient_id }}</div></td>
            <td>{{ rec.assigned_role.capitalize() }}</td>
            <td>{{ rec.department }}</td>
            <td><span class="grade" title="Minimum grade {{ rec.min_grade }}">{% for i in range(1, 6) %}<i class="{{ 'on' if i <= rec.min_grade }}"></i>{% endfor %}<span>{{ rec.min_grade }}</span></span></td>
            <td>{% if ok %}<span class="badge badge-ok">{{ icon('unlock') }} Eligible</span>{% else %}<span class="badge badge-locked">{{ icon('lock') }} Restricted</span>{% endif %}</td>
            <td class="act"><a href="{{ url_for('view_patient', record_role=rec.assigned_role, ehr_id=rec.ehr_id) }}" class="btn btn-sm {{ 'btn-secondary' if ok else 'btn-ghost' }}">View</a></td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
      <div class="empty" id="empty" {{ '' if not records else 'hidden' }}>No records match these filters.</div>
    </div>
  </section>

  {% if staff.role == 'admin' %}
  <aside class="side">
    <section class="card">
      <div class="card-head"><h2>Admin: Rotate Role Key</h2>{{ icon('key') }}</div>
      <div class="card-pad">
        <ul class="key-list" style="margin-bottom:16px">
          {% for k in key_status %}
          <li><span><b>{{ k.role.capitalize() }}</b><small class="mono">{{ k.key_id }}</small></span><small>Rotated {{ k.rotated }}</small></li>
          {% endfor %}
        </ul>
        <form method="post" action="{{ url_for('rotate_key') }}">
          <div class="field">
            <label for="rotate_role">Select Role for Key Rotation</label>
            <select class="select" name="role" id="rotate_role">
              {% for r in roles %}<option value="{{ r }}">{{ r.capitalize() }}</option>{% endfor %}
            </select>
            <span class="hint">Issues a fresh 256-bit key for the selected role.</span>
          </div>
          <button type="submit" class="btn btn-caution btn-block">{{ icon('refresh') }} Rotate Key</button>
        </form>
      </div>
    </section>
    <section class="card card-pad">
      <h2 style="margin-bottom:14px">Access policy</h2>
      <ul class="policy">
        <li>{{ icon('check') }}<span><b>Role</b> must match the record's assigned role.</span></li>
        <li>{{ icon('check') }}<span><b>Department</b> must match the record's department.</span></li>
        <li>{{ icon('check') }}<span><b>Grade</b> must meet the record's minimum.</span></li>
      </ul>
    </section>
  </aside>
  {% endif %}
</div>
{% endblock %}
{% block scripts %}
<script>
(function () {
  var table = document.getElementById('records');
  if (!table) return;
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var q = document.getElementById('q'), dept = document.getElementById('dept'), access = document.getElementById('access');
  var count = document.getElementById('count'), empty = document.getElementById('empty');

  function applyFilters() {
    var term = q.value.trim().toLowerCase(), shown = 0;
    rows.forEach(function (r) {
      var text = (r.dataset.ehr + ' ' + r.dataset.pid + ' ' + r.dataset.name + ' ' + r.dataset.dept + ' ' + r.dataset.role).toLowerCase();
      var visible = (!term || text.indexOf(term) !== -1) && (!dept.value || r.dataset.dept === dept.value) && (!access.value || r.dataset.access === access.value);
      r.hidden = !visible;
      if (visible) shown++;
    });
    count.textContent = shown === rows.length ? rows.length + ' records' : shown + ' of ' + rows.length + ' records';
    empty.hidden = shown !== 0;
  }
  [q, dept, access].forEach(function (el) { el.addEventListener('input', applyFilters); });

  Array.prototype.forEach.call(table.tHead.querySelectorAll('th[data-key]'), function (th) {
    th.querySelector('button').addEventListener('click', function () {
      var key = th.dataset.key, numeric = th.dataset.type === 'num';
      var dir = th.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
      table.tHead.querySelectorAll('th').forEach(function (h) { h.removeAttribute('aria-sort'); var a = h.querySelector('.arrow'); if (a) a.textContent = '▲▼'; });
      th.setAttribute('aria-sort', dir);
      th.querySelector('.arrow').textContent = dir === 'ascending' ? '▲' : '▼';
      rows.sort(function (a, b) {
        var x = a.dataset[key], y = b.dataset[key];
        var c = numeric ? x - y : x.localeCompare(y);
        return dir === 'ascending' ? c : -c;
      });
      rows.forEach(function (r) { tbody.appendChild(r); });
    });
  });
})();
</script>
{% endblock %}""",

    # ---------------------------------------------------------- patient hash
    "patient_hash.html": """{% extends "app_layout.html" %}
{% block title %}SecureEHR · Enter Patient Hash Key{% endblock %}
{% block page_class %}page-narrow{% endblock %}
{% block content %}
<section class="card card-pad">
  <p class="eyebrow">Step 3 of 4 · EHR {{ '%03d' % ehr_id }}</p>
  <h1 style="margin:8px 0 10px">Additional Verification</h1>
  <p class="muted" style="margin-bottom:24px">An email with the Patient Hash Key has been sent to your registered email address.
     Please enter it below to view the record.</p>
  <form method="post" action="{{ url_for('verify_patient_hash', record_role=record_role, ehr_id=ehr_id) }}">
    <div class="field">
      <label for="patient_hash">Patient Hash Key</label>
      <input type="text" class="input hash" id="patient_hash" name="patient_hash" placeholder="32-character hexadecimal key" maxlength="64" autocomplete="off" spellcheck="false" required autofocus>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button type="submit" class="btn btn-primary" style="flex:1">{{ icon('unlock') }} Verify &amp; View Record</button>
      <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
    </div>
  </form>
</section>
{% endblock %}""",

    # ---------------------------------------------------------------- record
    "record.html": """{% extends "app_layout.html" %}
{% block title %}SecureEHR · Record Details - EHR {{ record.ehr_id if record else '' }}{% endblock %}
{% block content %}
<a class="back-link" href="{{ url_for('dashboard') }}" style="margin:0 0 16px">{{ icon('arrow-left') }} Back to Dashboard</a>
{% if record %}
{% set is_admin = record.assigned_role == 'admin' %}
<article class="card">
  <div class="record-head">
    <div>
      <p class="eyebrow">{{ 'Administrative record' if is_admin else 'Record Details' }} · EHR ID: {{ record.ehr_id }}</p>
      <h1>{{ record.patient_name if not is_admin else record.subject_name }}</h1>
      <p class="muted mono" style="margin-top:6px">
        {{ record.patient_id }}{% if not is_admin %} · {{ record.mrn }}{% else %} · {{ record.subject_role.capitalize() }}{% endif %}
      </p>
    </div>
    <div class="badges">
      <span class="badge badge-ok">{{ icon('unlock') }} Decrypted</span>
      <span class="badge">{{ icon('key') }} <span class="mono">{{ record.key_id }}</span></span>
    </div>
  </div>
  <dl class="kv" style="margin:0">
    <div><dt>Department</dt><dd>{{ record.department }}</dd></div>
    <div><dt>{{ 'Performed By' if is_admin else 'Attending' }}</dt><dd>{{ record.attending_name or record.attending_id }}</dd></div>
    <div><dt>Visit Type</dt><dd>{{ record.visit_type }}</dd></div>
    <div><dt>Min Grade Required</dt><dd><span class="grade">{% for i in range(1, 6) %}<i class="{{ 'on' if i <= record.min_grade }}"></i>{% endfor %}<span>{{ record.min_grade }}</span></span></dd></div>
  </dl>
  {% if not is_admin %}
  <dl class="kv" style="margin:0">
    <div><dt>Age</dt><dd>{{ record.age }}</dd></div>
    <div><dt>Sex</dt><dd>{{ record.sex }}</dd></div>
    <div><dt>Blood Type</dt><dd class="mono">{{ record.blood_type }}</dd></div>
    <div><dt>Recorded</dt><dd class="mono">{{ record.timestamp.replace('T', ' ')[:16] }}</dd></div>
  </dl>
  {% endif %}
  <div class="notes">
    <section><h2>{{ 'Action' if is_admin else 'Diagnosis' }}</h2><p>{{ record.diagnosis }}</p></section>
    <section><h2>{{ 'Details' if is_admin else 'Treatment' }}</h2><p>{{ record.treatment }}</p></section>
  </div>
  {% if not is_admin %}
  <div class="notes">
    <section><h2>Medications</h2><p>{{ record.medications }}</p></section>
    <section><h2>Allergies &amp; Chronic Conditions</h2><p>{{ record.allergies }}{% if record.chronic_conditions %} · {{ record.chronic_conditions }}{% endif %}</p></section>
  </div>
  {% endif %}
  <div class="record-foot">
    <span>{{ icon('shield') }} Released by the context-aware policy engine after OTP and patient-hash verification.</span>
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary btn-sm">Back to Dashboard</a>
  </div>
</article>
{% else %}
<section class="card denied">
  <div class="ring">{{ icon('lock') }}</div>
  <h2>Access Denied or Record Not Found.</h2>
  <p class="muted" style="margin-top:6px">Return to the dashboard to choose another record.</p>
</section>
{% endif %}
{% endblock %}""",
}

# -----------------------------------------------------------------------------
# Flask Application Factory for Testing & Deployment
# -----------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.secret_key = os.urandom(24)  # Secure secret for session management.
    app.jinja_loader = DictLoader(TEMPLATES)

    # -------------------------------------------------------------------------
    # Flask Routes
    # -------------------------------------------------------------------------
    @app.route('/')
    def home():
        return render_template('home.html', roles=ROLES, step=1)

    @app.route('/select_role')
    def select_role():
        role = request.args.get('role')
        if role not in ROLES:
            flash("Invalid role selected.", "error")
            return redirect(url_for('home'))
        return redirect(url_for('login_page', role=role))

    @app.route('/login/<role>', methods=['GET'])
    def login_page(role):
        if role not in ROLES:
            abort(404)
        return render_template('login.html', role=role, step=2)

    @app.route('/request_otp/<role>', methods=['POST'])
    def request_otp(role):
        if role not in ROLES:
            abort(404)
        staff_id = request.form.get('staff_id')
        if not staff_id or staff_id not in staff_members or staff_members[staff_id]["role"] != role:
            flash("Invalid Staff ID for role '{}'.".format(role), "error")
            return redirect(url_for('login_page', role=role))
        # Generate a secure OTP (6-digit hex string).
        otp = secrets.token_hex(3)
        session['otp'] = otp
        session['otp_staff_id'] = staff_id
        session['otp_role'] = role
        logging.info(f"[OTP] Generated OTP for {staff_id} ({role}): {otp} sent to {staff_members[staff_id]['email']}")
        flash("OTP has been sent to your registered email.", "success")
        return redirect(url_for('login_page', role=role))

    @app.route('/login/<role>', methods=['POST'])
    def login_role(role):
        if role not in ROLES:
            abort(404)
        staff_id = request.form.get('staff_id')
        otp_input = request.form.get('otp')
        stored_otp = session.get('otp')
        otp_staff_id = session.get('otp_staff_id')
        otp_role = session.get('otp_role')
        if not staff_id or staff_id not in staff_members:
            flash("Invalid Staff ID. Please request an OTP first.", "error")
            return redirect(url_for('login_page', role=role))
        if not stored_otp or not otp_input or staff_id != otp_staff_id or otp_input != stored_otp or role != otp_role:
            flash("Invalid OTP. Please try again or request a new OTP.", "error")
            return redirect(url_for('login_page', role=role))
        # Successful login.
        session['staff'] = {
            "id": staff_id,
            "name": staff_members[staff_id]["name"],
            "email": staff_members[staff_id]["email"],
            "role": staff_members[staff_id]["role"],
            "department": staff_members[staff_id].get("department", ""),
            "grade": staff_members[staff_id].get("grade", 0)
        }
        session.pop('otp', None)
        session.pop('otp_staff_id', None)
        session.pop('otp_role', None)
        return redirect(url_for('dashboard'))

    @app.route('/dashboard', methods=['GET'])
    def dashboard():
        staff = session.get('staff')
        if not staff:
            flash("Please log in first.", "warning")
            return redirect(url_for('home'))

        # Check if the user is level 5
        is_level_5 = staff.get("grade") == 5

        # Filter records based on department or show all records for level 5 users
        if is_level_5:
            filtered_records = [rec for records in synthetic_records.values() for rec in records]
        else:
            filtered_records = [
                rec for records in synthetic_records.values() for rec in records
                if rec["department"] == staff.get("department")
            ]

        # Key status for the admin key-rotation panel.
        key_status = [
            {
                "role": r,
                "key_id": f"{r.upper()}_AES256",
                "rotated": time.strftime('%d %b, %H:%M', time.localtime(key_manager.keys[r][1]))
            }
            for r in ROLES
        ]

        return render_template(
            'dashboard.html',
            staff=staff,
            records=filtered_records,
            roles=ROLES,
            selected_role=staff["role"],
            key_status=key_status
        )

    # ehr_id is only unique within a role, so the record's role is part of the URL.
    @app.route('/view_patient/<record_role>/<int:ehr_id>', methods=['GET'])
    def view_patient(record_role, ehr_id):
        staff = session.get('staff')
        if not staff:
            flash("Please log in first.", "warning")
            return redirect(url_for('home'))
        # Check if the record exists in the synthetic set.
        record = next((rec for rec in synthetic_records.get(record_role, []) if rec["ehr_id"] == ehr_id), None)
        if not record:
            flash("Record not found.", "error")
            return redirect(url_for('dashboard'))
        # Check if the user's department matches the record's department.
        if staff.get("department") != record.get("department"):
            flash(f"Access denied. You can only view records related to your department: {staff.get('department')}.", "error")
            return redirect(url_for('dashboard'))  # Redirect back to the dashboard with the flash message.
        # Evaluate access using the extended context-aware engine.
        key = policy_engine.evaluate_access(staff, record)
        if key is None:
            flash("Access denied due to department or experience level mismatch.", "error")
            return redirect(url_for('dashboard'))
        # Simulate sending the patient hash key to the user's email.
        logging.info(f"[Patient Hash] Sent patient hash for EHR {ehr_id} to {staff['email']}: {record['patient_hash']}")
        flash("A patient hash key has been sent to your registered email.", "info")
        return render_template('patient_hash.html', record_role=record_role, ehr_id=ehr_id)

    # Verify patient hash key and display record if correct.
    @app.route('/verify_patient_hash/<record_role>/<int:ehr_id>', methods=['POST'])
    def verify_patient_hash(record_role, ehr_id):
        staff = session.get('staff')
        if not staff:
            flash("Please log in first.", "warning")
            return redirect(url_for('home'))
        # Retrieve the record.
        record = next((rec for rec in synthetic_records.get(record_role, []) if rec["ehr_id"] == ehr_id), None)
        if not record:
            flash("Record not found.", "error")
            return redirect(url_for('dashboard'))
        # Check the submitted patient hash.
        submitted_hash = request.form.get('patient_hash')
        if submitted_hash != record["patient_hash"]:
            flash("Incorrect Patient Hash Key. Please try again.", "error")
            return redirect(url_for('view_patient', record_role=record_role, ehr_id=ehr_id))
        # Patient hash is correct. Now retrieve and decrypt the record.
        key = policy_engine.evaluate_access(staff, record)
        if key is None:
            flash("Access denied.", "error")
            return redirect(url_for('dashboard'))
        enc_record = encrypted_records.get(record_role, {}).get(ehr_id)
        if not enc_record:
            flash("Encrypted record not found.", "error")
            return redirect(url_for('dashboard'))
        try:
            decrypted_record = decrypt_record(enc_record, key)
        except Exception as e:
            logging.error("Decryption error: " + str(e))
            flash("Decryption failed.", "error")
            return redirect(url_for('dashboard'))
        decrypted_record["ehr_id"] = ehr_id
        return render_template('record.html', record=decrypted_record)

    @app.route('/rotate_key', methods=['POST'])
    def rotate_key():
        staff = session.get('staff')
        if not staff or staff.get("role") != "admin":
            flash("Only admin users can rotate keys.", "error")
            return redirect(url_for('dashboard'))
        role = request.form.get('role')
        if role in ROLES:
            key_manager.rotate_key(role)
            flash(f"Encryption key for role '{role}' has been rotated.", "success")
        else:
            flash("Invalid role selected.", "error")
        return redirect(url_for('dashboard'))

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('home'))

    return app

# -----------------------------------------------------------------------------
# Testing Environment using unittest and Flask's test client
# -----------------------------------------------------------------------------
class HospitalLoginTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app.testing = True

    def test_home_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Select Your Role", response.data)

    def test_invalid_role_redirect(self):
        response = self.client.get('/login/invalidrole')
        self.assertEqual(response.status_code, 404)

    def test_otp_request_and_login_failure(self):
        response = self.client.post('/request_otp/doctor', data={"staff_id": "INVALID"}, follow_redirects=True)
        self.assertIn(b"Invalid Staff ID", response.data)
        response = self.client.post('/login/doctor', data={"staff_id": "DOC001", "otp": "000000"}, follow_redirects=True)
        self.assertIn(b"Invalid OTP", response.data)

    def test_successful_login_and_patient_hash_verification(self):
        with self.client as c:
            response = c.post('/request_otp/doctor', data={"staff_id": "DOC001"}, follow_redirects=True)
            self.assertIn(b"OTP has been sent", response.data)
            with c.session_transaction() as sess:
                otp = sess.get('otp')
            self.assertIsNotNone(otp)
            response = c.post('/login/doctor', data={"staff_id": "DOC001", "otp": otp}, follow_redirects=True)
            self.assertIn(b"Dashboard", response.data)
            # Pick a doctor record DOC001 is allowed to open (department and grade match).
            staff = staff_members["DOC001"]
            record = next((rec for rec in synthetic_records["doctor"]
                           if rec["department"] == staff["department"] and rec["min_grade"] <= staff["grade"]), None)
            self.assertIsNotNone(record)
            ehr_id = record["ehr_id"]
            response = c.get(f'/view_patient/doctor/{ehr_id}', follow_redirects=True)
            self.assertIn(b"Additional Verification", response.data)
            # Submit the expected patient hash from the synthetic record.
            patient_hash = record["patient_hash"]
            response = c.post(f'/verify_patient_hash/doctor/{ehr_id}', data={"patient_hash": patient_hash}, follow_redirects=True)
            self.assertIn(b"Record Details", response.data)
            self.assertIn(record["patient_id"].encode(), response.data)
            # The same ehr_id under another role is a different record and must stay denied.
            nurse_record = next(rec for rec in synthetic_records["nurse"] if rec["ehr_id"] == ehr_id)
            response = c.post(f'/verify_patient_hash/nurse/{ehr_id}', data={"patient_hash": nurse_record["patient_hash"]}, follow_redirects=True)
            self.assertNotIn(b"Record Details", response.data)
            self.assertIn(b"Access denied", response.data)

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    if '--test' in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        app = create_app()
        app.run(debug=True)
