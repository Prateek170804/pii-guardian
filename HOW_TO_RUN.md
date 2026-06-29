# How to run pii-guardian

## 1. Requirements
- Python 3.10+  (3.12 recommended)
- One dependency: PyYAML

## 2. Install
```bash
cd pii-guardian
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```
(Windows: activate with `.venv\Scripts\activate`)

## 3. Run on the included demo data
```bash
python run.py --schema inputs/schema/columns.csv \
              --samples inputs/samples/samples.json \
              --config config \
              --out outputs
```
Results appear in `outputs/`:
- classification_catalog.csv / .json  — every column, its category, tier, confidence, decision
- review_queue.csv                    — low-confidence columns for a human to confirm
- change_report.md                    — new/removed columns vs the previous run
- runbook.md                          — apply order, validation, grants, rollback
- sql/                                 — the Snowflake scripts to apply (run in order 00 -> 40)

## 4. See the "new data arrived" loop
Run again on the v2 schema (which adds CLAIMANT_SSN); the change report flags it:
```bash
python run.py --schema inputs/schema/columns_v2.csv \
              --samples inputs/samples/samples.json \
              --config config --out outputs
cat outputs/change_report.md
```

## 5. Use your own data
1. Export your columns to CSV with headers:
   TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,DATA_TYPE,COMMENT
   (from Snowflake: SELECT ... FROM <DB>.INFORMATION_SCHEMA.COLUMNS)
2. (Optional) Provide a redacted samples JSON: {"DB.SCHEMA.TABLE.COLUMN": ["val1","val2"]}
3. Tune config/cde_dictionary.yaml (your naming) and config/roles.yaml (who sees what).
4. Re-run step 3 above.

## 6. Apply the protection (human step)
The tool never connects to Snowflake. A privileged person reviews outputs/sql/ and runs,
in order: 00_tags -> 10_roles -> 20_masking_policies -> 30_classification_tags -> 40_apply_masking,
then 99_validation to confirm masked vs cleartext per role. See runbook.md.

## Quick sanity check
```bash
python -m py_compile run.py pii_guardian/*.py
```
