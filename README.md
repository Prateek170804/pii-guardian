# pii-guardian

Connection-free agent that **discovers and classifies sensitive customer data** (PII / PHI /
financial) from schema metadata, then **generates Snowflake governance-as-code** that hides the
cleartext from everyone except authorized roles — using tag-based classification + Dynamic Data
Masking, with optional column-level encryption for the most sensitive fields.

It never connects to Snowflake. A human with a privileged role reviews and runs the generated SQL.
That separation is deliberate: it keeps credentials out of the tool and gives you a clean audit story.

## Quickstart

```bash
pip install pyyaml
python run.py \
  --schema  inputs/schema/columns.csv \
  --samples inputs/samples/samples.json \
  --config  config \
  --out     outputs
```

- `--schema` is an export of `INFORMATION_SCHEMA.COLUMNS` (or `SNOWFLAKE.ACCOUNT_USAGE.COLUMNS`).
  Columns used: `TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, COMMENT`.
- `--samples` (optional) is a JSON map of `DB.SCHEMA.TABLE.COLUMN -> [sample values]`, **redacted**.
  It improves accuracy via value-format detection (SSN, email, phone, card-with-Luhn, ZIP, date).

## What it produces (`outputs/`)

| File | Purpose |
|---|---|
| `classification_catalog.json` / `.csv` | Every column with category, sensitivity tier, confidence, decision, mask behavior. **Metadata only — no raw values.** |
| `review_queue.csv` | Low-confidence / ambiguous columns for human review (never auto-applied). |
| `change_report.md` | New / removed columns vs the last run (the continuous-discovery loop). |
| `runbook.md` | Ordered apply steps, validation, grants, rollback, guardrails. |
| `sql/00_tags.sql` | Classification tags. |
| `sql/10_roles.sql` | Privileged read roles. |
| `sql/20_masking_policies.sql` | Masking policies (only those actually used). |
| `sql/30_classification_tags.sql` | Apply tags to columns. |
| `sql/40_apply_masking.sql` | Apply masking policies to columns. |
| `sql/50_tag_based_masking_optional.sql` | Alternative inheritance-based masking (commented). |
| `sql/60_encryption_optional.sql` | Optional top-tier column encryption (commented templates). |
| `sql/99_validation.sql` | Per-role SELECTs to prove masking behaves. |

## How classification works

1. **Name detection** — column names matched against a P&C CDE dictionary (`config/cde_dictionary.yaml`),
   tested against both underscore and space-separated forms so `\bssn\b` catches `claimant_ssn`.
2. **Value detection** — regex + Luhn checks over redacted samples; returns a format label + match ratio,
   never the values themselves.
3. **Fusion & scoring** — signals combine into a confidence score; a strong, specific name match wins the
   category over a generic value guess. Thresholds route each column to **auto / review / ignore**
   (`config/taxonomy.yaml`).
4. **Masking behavior** — chosen per field (SSN→last-4, email→domain-only, card→last-4, else full mask),
   recorded in the catalog so SQL generation is deterministic (`config/masking_rules.yaml`).

## Continuous loop

Each run snapshots the inventory (`snapshots/`). The next run diffs against it, so newly arrived
tables/columns are detected, classified, and protected — this is the "scans new data arriving" behavior.

## Tuning

All behavior lives in `config/`: extend the CDE dictionary, adjust tiers/thresholds/weights, change the
role model, or add fields to `encrypt_columns`. No code changes needed for routine tuning.
