# CLAUDE.md — operating rules for this project

This is a **connection-free** sensitive-data discovery and protection tool. When working in this repo,
follow these rules:

## Hard rules
1. **Never connect to Snowflake or any live system.** This tool only reads files and writes files
   (catalog, review queue, SQL, runbook). A human applies the SQL.
2. **Never write raw sensitive values into any output** — not the catalog, logs, review queue, or commit
   messages. Outputs hold only column metadata, category labels, format labels, and match ratios.
3. **Never auto-apply protection to low-confidence columns.** Anything below the high threshold goes to
   `review_queue.csv` for a human. Lean toward recall (flag for review) over silently ignoring.
4. **Generated SQL must stay idempotent** (`IF NOT EXISTS`, no destructive statements) and must never run
   as `ACCOUNTADMIN`.

## When extending
- Add detection patterns in `config/cde_dictionary.yaml`; keep regexes RE2-compatible (no lookahead/behind)
  so they behave the same in Snowflake masking policies.
- New masking behaviors: add the policy body in `pii_guardian/sqlgen.py` `_POLICY_DEFS` and reference it
  from `config/masking_rules.yaml`. Keep the catalog as the single source of truth for behavior selection.
- Treat false negatives (missed PII) as the highest-severity bug class. Add a regression sample whenever
  one is found.

## Sanity checks before declaring done
- `python -m py_compile run.py pii_guardian/*.py`
- Run baseline + a modified schema; confirm new sensitive columns appear in `change_report.md`.
- Spot-check `review_queue.csv` for false positives and the catalog for false negatives.
