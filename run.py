#!/usr/bin/env python3
"""pii-guardian — discover, classify, and generate protection for sensitive data.

Connection-free: reads schema/sample files, writes a classification catalog,
a human review queue, idempotent Snowflake SQL, and a rollout runbook.
A privileged human reviews and runs the SQL; this tool never touches Snowflake.

Usage:
    python run.py --schema inputs/schema/columns.csv \
                  --samples inputs/samples/samples.json \
                  --config config --out outputs
"""
import argparse
import csv
import json
import os
import datetime as dt

import yaml

from pii_guardian.ingest import load_inventory
from pii_guardian.classify import classify_all
from pii_guardian.sqlgen import generate
from pii_guardian.diff import load_snapshot, save_snapshot, diff


def _load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description="Discover & protect sensitive data.")
    ap.add_argument("--schema", required=True, help="INFORMATION_SCHEMA.COLUMNS CSV")
    ap.add_argument("--samples", help="JSON map of fqcn -> [sample values] (optional)")
    ap.add_argument("--config", default="config", help="config directory")
    ap.add_argument("--out", default="outputs", help="output directory")
    ap.add_argument("--snapshot", default="snapshots/inventory.json")
    args = ap.parse_args()

    cde = _load_yaml(os.path.join(args.config, "cde_dictionary.yaml"))
    taxonomy = _load_yaml(os.path.join(args.config, "taxonomy.yaml"))
    roles_cfg = _load_yaml(os.path.join(args.config, "roles.yaml"))
    masking_rules = _load_yaml(os.path.join(args.config, "masking_rules.yaml"))

    columns = load_inventory(args.schema)
    samples_map = {}
    if args.samples and os.path.exists(args.samples):
        with open(args.samples, encoding="utf-8") as f:
            samples_map = {k: v for k, v in json.load(f).items() if not k.startswith("_")}

    # continuous-loop diff vs previous snapshot
    prev = load_snapshot(args.snapshot)
    delta = diff(prev, columns)

    results = classify_all(columns, samples_map, cde, taxonomy, masking_rules)
    auto = [c for c in results if c.decision == "auto"]
    review = [c for c in results if c.decision == "review"]

    os.makedirs(args.out, exist_ok=True)
    sql_dir = os.path.join(args.out, "sql")
    os.makedirs(sql_dir, exist_ok=True)

    # 1) classification catalog (metadata only) ------------------------------
    with open(os.path.join(args.out, "classification_catalog.json"), "w", encoding="utf-8") as f:
        json.dump([c.to_dict() for c in results], f, indent=2)
    with open(os.path.join(args.out, "classification_catalog.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fqcn", "data_type", "category", "sensitivity", "confidence",
                    "decision", "mask_behavior"])
        for c in results:
            w.writerow([c.fqcn, c.data_type, c.category or "", c.sensitivity or "",
                        c.confidence, c.decision, c.mask_behavior or ""])

    # 2) review queue --------------------------------------------------------
    with open(os.path.join(args.out, "review_queue.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fqcn", "data_type", "suspected_category", "confidence", "signals"])
        for c in review:
            w.writerow([c.fqcn, c.data_type, c.category or "", c.confidence,
                        json.dumps(c.signals)])

    # 3) SQL -----------------------------------------------------------------
    files, applied = generate(results, roles_cfg, masking_rules)
    for name, content in files.items():
        with open(os.path.join(sql_dir, name), "w", encoding="utf-8") as f:
            f.write(content)

    # 4) change report (continuous loop) ------------------------------------
    added_auto = [c for c in results if c.fqcn in set(delta["added"]) and c.decision == "auto"]
    with open(os.path.join(args.out, "change_report.md"), "w", encoding="utf-8") as f:
        f.write(f"# Change report — {dt.datetime.now().isoformat(timespec='seconds')}\n\n")
        if delta["is_baseline"]:
            f.write("Baseline run (no prior snapshot). All columns treated as initial load.\n")
        else:
            f.write(f"- New columns since last run: **{len(delta['added'])}**\n")
            f.write(f"- Removed columns: **{len(delta['removed'])}**\n\n")
            if added_auto:
                f.write("## Newly arrived sensitive columns (auto-classified)\n\n")
                f.write("| Column | Category | Sensitivity | Confidence | Masking |\n")
                f.write("|---|---|---|---|---|\n")
                for c in added_auto:
                    f.write(f"| {c.fqcn} | {c.category} | {c.sensitivity} | "
                            f"{c.confidence} | {c.mask_behavior} |\n")
            for fq in delta["added"]:
                if fq not in {c.fqcn for c in added_auto}:
                    f.write(f"- new (non-auto): {fq}\n")

    # 5) runbook -------------------------------------------------------------
    _write_runbook(args.out, results, auto, review, applied, roles_cfg)

    # 6) snapshot for next run ----------------------------------------------
    os.makedirs(os.path.dirname(args.snapshot), exist_ok=True)
    save_snapshot(args.snapshot, columns)

    # console summary
    print(f"Scanned columns      : {len(results)}")
    print(f"Auto-classified      : {len(auto)}")
    print(f"Sent to review queue : {len(review)}")
    print(f"Ignored (not sensitive): {len(results) - len(auto) - len(review)}")
    if not delta["is_baseline"]:
        print(f"New columns this run : {len(delta['added'])} ({len(added_auto)} sensitive)")
    print(f"SQL scripts written  : {len(files)} -> {sql_dir}")


def _write_runbook(out, results, auto, review, applied, roles_cfg):
    full = roles_cfg["roles"]["full_reader"]
    partial = roles_cfg["roles"]["partial_reader"]
    lines = []
    a = lines.append
    a("# Rollout runbook\n")
    a(f"_Generated {dt.datetime.now().isoformat(timespec='seconds')}._\n")
    a("## Summary\n")
    a(f"- Columns scanned: **{len(results)}**")
    a(f"- Auto-classified & protected: **{len(auto)}**")
    a(f"- Awaiting human review: **{len(review)}**\n")
    a("## Apply order (review each script first)\n")
    a("Run as a role with DDL rights on the governance schema and target tables "
      "(e.g. SECURITYADMIN/SYSADMIN per your model) — **not** ACCOUNTADMIN.\n")
    for i, s in enumerate(["00_tags.sql", "10_roles.sql", "20_masking_policies.sql",
                           "30_classification_tags.sql", "40_apply_masking.sql"], 1):
        a(f"{i}. `sql/{s}`")
    a("\nOptional: `sql/50_tag_based_masking_optional.sql`, `sql/60_encryption_optional.sql`.\n")
    a("## Validate\n")
    a(f"Run `sql/99_validation.sql`. A default role must see masked output; "
      f"`{partial}` partial; `{full}` cleartext.\n")
    a("## Grant access (out of band)\n")
    a(f"- `GRANT ROLE {full} TO USER <authorized_user>;`")
    a(f"- `GRANT ROLE {partial} TO USER <support_user>;`")
    a("- Do NOT grant either role to analyst/reporting roles.\n")
    a("## Rollback\n")
    a("Per protected column: `ALTER TABLE <t> MODIFY COLUMN <c> UNSET MASKING POLICY;` "
      "then `UNSET TAG ...`. Drop policies/tags only after detaching from all columns.\n")
    a("## Guardrails\n")
    a("- This catalog stores metadata only — no raw sensitive values.")
    a("- Low-confidence columns are quarantined to `review_queue.csv`, never auto-applied.")
    a("- The generator never connects to Snowflake; a human applies the SQL.")
    with open(os.path.join(out, "runbook.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
