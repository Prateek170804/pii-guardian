#!/usr/bin/env python3
"""Regression tests for value/name detection and confidence scoring.

Plain Python (no pytest dependency). Run:  python tests/test_detection.py

Captures two things that must hold together:
  1. The demo's real PII keeps its known confidences/decisions (no regression).
  2. Plain numeric ID/count columns are NOT mislabelled as CONTACT/auto just
     because they are 5 or 10 digits long (the bug fixed by detector specificity +
     the separator-required phone regex). Formatted phones / dashed SSNs are still
     caught, and a *named* ZIP column with bare 5-digit values still scores high.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
from pii_guardian.ingest import Column, load_inventory
from pii_guardian.classify import Classifier, classify_all

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(ROOT, "config")


def _cfg(name):
    with open(os.path.join(CFG, name), encoding="utf-8") as f:
        return yaml.safe_load(f)


CDE, TAX, MR = _cfg("cde_dictionary.yaml"), _cfg("taxonomy.yaml"), _cfg("masking_rules.yaml")
CLF = Classifier(CDE, TAX, MR)

_results = []


def check(label, cond):
    _results.append((label, bool(cond)))
    print(("PASS" if cond else "FAIL") + "  " + label)


def classify_one(name, samples):
    col = Column("DB", "SCHEMA", "TBL", name, "", "OTHER")
    return CLF.classify(col, samples)


# --- 1. demo golden values (regression guard) ------------------------------
cols = load_inventory(os.path.join(ROOT, "inputs/schema/columns.csv"))
samples = {k: v for k, v in json.load(
    open(os.path.join(ROOT, "inputs/samples/samples.json"), encoding="utf-8")).items()
    if not k.startswith("_")}
demo = {c.fqcn: c for c in classify_all(cols, samples, CDE, TAX, MR)}
GOLD = [
    ("RAW_DB.POLICY.POLICYHOLDER.SSN", "GOV_ID", 0.95, "auto"),
    ("RAW_DB.POLICY.POLICYHOLDER.EMAIL", "CONTACT", 0.85, "auto"),
    ("RAW_DB.POLICY.POLICYHOLDER.PHONE", "CONTACT", 0.95, "auto"),
    ("RAW_DB.POLICY.POLICYHOLDER.ZIP_CODE", "CONTACT", 0.95, "auto"),
    ("RAW_DB.POLICY.POLICYHOLDER.DATE_OF_BIRTH", "QUASI_IDENTIFIER", 0.95, "auto"),
    ("RAW_DB.BILLING.PAYMENT.CARD_NUMBER", "FINANCIAL", 0.95, "auto"),
    ("RAW_DB.BILLING.PAYMENT.BANK_ACCOUNT_NUMBER", "FINANCIAL", 0.9, "auto"),
]
for fq, cat, conf, dec in GOLD:
    c = demo[fq]
    check(f"demo {fq.split('.')[-1]} = {cat}/{conf}/{dec}",
          c.category == cat and abs(c.confidence - conf) < 0.005 and c.decision == dec)

# --- 2. numeric ID/count columns must score BELOW review (would be ignored) -
# Assert on confidence (the thing the fix changed): these scored ~0.85 before and
# must now fall under the low threshold. Confidence is independent of type_group,
# unlike the final auto/review decision.
TEN = ["0000021476", "0000070286", "0000077606", "0000083485", "0000001607"]   # bare 10-digit
FIVE = ["77008", "87253", "35375", "51436", "99430"]                            # bare 5-digit
for name, vals in [("POLICY_NO", TEN), ("PROG_ID_NO", TEN), ("POL_NOTE_DAYS_CNT", FIVE),
                   ("EXTRN_USR_OFF_CD", FIVE), ("LANGUAGE_ID", FIVE)]:
    r = classify_one(name, vals)
    check(f"numeric {name} below review threshold (got {r.category}/{r.confidence})",
          r.confidence < CLF.low)

# --- 3. genuine value formats are still detected (high confidence) ----------
fp = classify_one("CALLBACK", ["+1 415-555-0132", "(212) 555-0198", "650-555-0143",
                               "212.555.0177", "415 555 0190"])
check(f"formatted phone still high/CONTACT (got {fp.category}/{fp.confidence})",
      fp.category == "CONTACT" and fp.confidence >= CLF.high)

dssn = classify_one("TAXREF", ["123-45-6789", "987-65-4321", "234-56-7890"])
check(f"dashed SSN still high/GOV_ID (got {dssn.category}/{dssn.confidence})",
      dssn.category == "GOV_ID" and dssn.confidence >= CLF.high)

bssn = classify_one("REF9", ["123456789", "987654321", "234567890"])  # bare 9-digit
check(f"bare 9-digit -> review band, not auto (got {bssn.confidence})",
      CLF.low <= bssn.confidence < CLF.high)

# named ZIP column with bare 5-digit values: name corroboration keeps it high
z = classify_one("ZIP_CODE", FIVE)
check(f"named ZIP_CODE w/ bare-5 still high/CONTACT (got {z.category}/{z.confidence})",
      z.category == "CONTACT" and z.confidence >= CLF.high)

# --- 4. value-inspection guard: constant flag/code columns are suppressed ---
from pii_guardian.cellcrypto import _plan_scope
pk = _plan_scope("csv", ["KEY_ACCT_FG"], [["K"] * 15], CLF)[0]
check(f"constant weak-match column suppressed (plan={pk['plan']})", pk["plan"] == "skip")
pn = _plan_scope("csv", ["INSURED_NAME"],
                 [["NOVAK", "HORAK", "KOVAC", "MAREK", "DVORAK", "SVOBODA"]], CLF)[0]
check(f"varied name column still flagged (plan={pn['plan']})", pn["plan"] != "skip")

# Pre-check (recommend) is conservative: ONLY high-confidence auto columns.
check(f"auto column IS pre-checked (recommend={pn['recommend']})",
      pn["recommend"] is True and pn["plan"] == "auto")
pr = _plan_scope("csv", ["OWNER_NAME"],
                 [["NOVAK", "HORAK", "KOVAC", "MAREK", "DVORAK"]], CLF)[0]
check(f"review column NOT pre-checked (recommend={pr['recommend']}, plan={pr['plan']})",
      pr["recommend"] is False and pr["plan"] == "review")

# --- 4b. non-person 'X name' columns are not tagged as a person identifier ---
for col in ["GDW_SRC_FILE_NAME", "LOC_BLDG_NAME", "STREET_NAME", "POL_FORM_NAME",
            "ROOMS_STE_APT_NAME"]:
    r = classify_one(col, ["NOVAK", "HORAK", "KOVAC", "MAREK"])
    check(f"{col} not DIRECT_IDENTIFIER (got {r.category})", r.category != "DIRECT_IDENTIFIER")
own = classify_one("OWNER_NAME", ["NOVAK", "HORAK", "KOVAC", "MAREK"])
check(f"OWNER_NAME still DIRECT_IDENTIFIER (got {own.category})",
      own.category == "DIRECT_IDENTIFIER")

# --- 4c. skip columns expose no category in the plan ------------------------
lat = _plan_scope("csv", ["LATITUDE_MINUTE"],
                  [["94105", "10001", "60601", "30301", "98101", "12345"]], CLF)[0]
check(f"skip column has no category (plan={lat['plan']}, category={lat['category']})",
      lat["plan"] == "skip" and lat["category"] is None and lat["regulations"] == [])

# --- 5. regulatory dimension ------------------------------------------------
check("GOV_ID implicates GLBA", "GLBA" in CLF.regulations("GOV_ID"))
check("HEALTH implicates HIPAA", "HIPAA" in CLF.regulations("HEALTH"))
check("payment-card data implicates PCI", "PCI" in CLF.regulations("FINANCIAL", value_detector="card"))
check("non-card FINANCIAL is not PCI", "PCI" not in CLF.regulations("FINANCIAL"))
check("no category -> no regulations", CLF.regulations(None) == [])

# --- 6. 'NM' abbreviation recall (was a false negative) ---------------------
nm = classify_one("NRTH_AM_UND_NM_EXT", ["NOVAK", "HORAK", "KOVAC", "MAREK", "DVORAK"])
check(f"NM abbrev detected as DIRECT_IDENTIFIER (got {nm.category})",
      nm.category == "DIRECT_IDENTIFIER")

# --- 7. coarse geo is QUASI_IDENTIFIER; precise contact stays CONTACT -------
for col in ["CITY", "TOWN_CD", "COUNTY_CD"]:
    r = classify_one(col, ["Austin", "Reno", "Mesa", "Dallas"])
    check(f"{col} -> QUASI_IDENTIFIER (got {r.category})", r.category == "QUASI_IDENTIFIER")
for col, vals in [("EMAIL", ["a@b.com", "c@d.com", "e@f.com"]),
                  ("ZIP_CODE", ["94105", "10001", "60601"]),
                  ("STREET_ADDRESS", ["1 Main St", "2 Oak Ave", "3 Elm Rd"])]:
    r = classify_one(col, vals)
    check(f"{col} stays CONTACT (got {r.category})", r.category == "CONTACT")

# --- summary ----------------------------------------------------------------
passed = sum(1 for _, ok in _results if ok)
print(f"\n{passed}/{len(_results)} passed")
sys.exit(0 if passed == len(_results) else 1)
