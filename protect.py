#!/usr/bin/env python3
"""protect.py — encrypt / decrypt sensitive cells in a real CSV or XLSX file.

Companion CLI to run.py. run.py classifies schema metadata and emits Snowflake SQL;
this works on an actual data file, reusing the same PII detection to find sensitive
columns, then reversibly encrypting just those cells (Fernet / AES + HMAC).

  Preview:  python protect.py encrypt --in data.csv --key pii.key --dry-run
  Encrypt:  python protect.py encrypt --in data.csv --key pii.key
  Pick:     python protect.py encrypt --in data.csv --key pii.key --columns INSURED_NAME,ASM_INSURED_NAME
  Decrypt:  python protect.py decrypt --in data.protected.csv --key pii.key

Default selection is the *recommended* set (strong name matches + specific value
formats); loose numeric matches are surfaced but not pre-selected. Connection-free.
Never logs raw values — plan, console and manifest hold metadata only.
"""
import argparse
import datetime as dt
import json
import os

from cryptography.fernet import Fernet

from pii_guardian.cellcrypto import (
    MARKER, make_classifier, build_plan, file_kind,
    load_or_create_key, load_key, encrypt_file, decrypt_file,
)


def _default_out(in_path, mode):
    root, ext = os.path.splitext(in_path)
    if mode == "decrypt" and root.endswith(".protected"):
        root = root[: -len(".protected")]
    return f"{root}{'.protected' if mode == 'encrypt' else '.decrypted'}{ext}"


def _print_plan(plan, selected_names):
    by_scope = {}
    for p in plan:
        by_scope.setdefault(p["scope"], []).append(p)
    for scope, entries in by_scope.items():
        flagged = [p for p in entries if p["plan"] != "skip"]
        print(f"  [{scope}]  ({len(entries)} columns, {len(flagged)} flagged)")
        if not flagged:
            print("    (no sensitive columns detected)")
            continue
        print(f"    {'sel':<3} {'column':<24} {'category':<18} {'conf':>5}  {'regulations':<20} evidence")
        print(f"    {'-'*3} {'-'*24} {'-'*18} {'-'*5}  {'-'*20} --------")
        for p in flagged:
            sel = " * " if p["name"] in selected_names else "   "
            ev = []
            if p["name_strength"]:
                ev.append(f"name:{p['name_strength']}")
            if p["value_detector"]:
                ev.append(f"value:{p['value_detector']}({p['value_ratio']})")
            regs = (",".join(p.get("regulations", [])) or "-")[:20]
            print(f"    {sel} {p['name'][:24]:<24} {str(p['category']):<18} "
                  f"{p['confidence']:>5.2f}  {regs:<20} {', '.join(ev)}")


def _select(plan, columns, include_review):
    if columns:
        want = {c.strip() for c in columns.split(",") if c.strip()}
        return {(p["scope"], p["name"]) for p in plan if p["name"] in want}
    sel = {(p["scope"], p["name"]) for p in plan if p["recommend"]}
    if include_review:
        sel |= {(p["scope"], p["name"]) for p in plan if p["plan"] in ("auto", "review")}
    return sel


def _write_manifest(path, in_path, key_path, entries):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "generated": dt.datetime.now().isoformat(timespec="seconds"),
            "source_file": os.path.basename(in_path),
            "key_file": os.path.basename(key_path),
            "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
            "marker": MARKER,
            "note": "Metadata only. No raw sensitive values are stored here.",
            "encrypted_columns": entries,
        }, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Encrypt/decrypt sensitive cells in a CSV/XLSX file.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("encrypt", help="detect sensitive columns and encrypt their cells")
    e.add_argument("--in", dest="inp", required=True, help="CSV or XLSX file")
    e.add_argument("--out", help="output file (default: <name>.protected.<ext>)")
    e.add_argument("--key", default="pii.key", help="key file (generated if absent)")
    e.add_argument("--config", default="config", help="detection config directory")
    e.add_argument("--columns", help="comma-separated column names to encrypt (overrides auto)")
    e.add_argument("--include-review", action="store_true",
                   help="also include borderline (review) columns, not just recommended")
    e.add_argument("--dry-run", action="store_true", help="show the plan only; write nothing")

    d = sub.add_parser("decrypt", help="decrypt cells previously encrypted by this tool")
    d.add_argument("--in", dest="inp", required=True, help="protected CSV or XLSX file")
    d.add_argument("--out", help="output file (default: <name>.decrypted.<ext>)")
    d.add_argument("--key", required=True, help="key file used at encrypt time")

    args = ap.parse_args()
    try:
        file_kind(args.inp)
    except ValueError as ex:
        raise SystemExit(f"error: {ex}")
    if not os.path.exists(args.inp):
        raise SystemExit(f"error: input file not found: {args.inp}")

    if args.cmd == "encrypt":
        clf = make_classifier(args.config)
        plan = build_plan(args.inp, clf)
        selected = _select(plan, args.columns, args.include_review)
        selected_names = {n for _, n in selected}

        if args.dry_run:
            print(f"DRY RUN - plan for {args.inp} ( * = will be encrypted; nothing written)\n")
            _print_plan(plan, selected_names)
            print(f"\nWould encrypt {len(selected)} column(s). "
                  f"Re-run without --dry-run to apply.")
            return

        out_path = args.out or _default_out(args.inp, "encrypt")
        key, created = load_or_create_key(args.key)
        fernet = Fernet(key)
        print(f"Encrypting {args.inp}")
        print(f"Key file   : {args.key}" + ("  (NEWLY GENERATED - back this up!)" if created else ""))
        print("Plan ( * = encrypting):")
        _print_plan(plan, selected_names)
        entries = encrypt_file(args.inp, out_path, fernet, selected, plan)
        manifest_path = os.path.splitext(out_path)[0] + ".manifest.json"
        _write_manifest(manifest_path, args.inp, args.key, entries)
        total = sum(en["encrypted_cells"] for en in entries)
        print(f"\nEncrypted columns : {len(entries)}")
        print(f"Encrypted cells   : {total}")
        print(f"Protected file    : {out_path}")
        print(f"Manifest          : {manifest_path}")
        print("WARNING: keep the key file safe - without it the data cannot be decrypted.")
    else:  # decrypt
        out_path = args.out or _default_out(args.inp, "decrypt")
        if not os.path.exists(args.key):
            raise SystemExit(f"error: key file not found: {args.key}")
        fernet = Fernet(load_key(args.key))
        print(f"Decrypting {args.inp} with key {args.key}")
        n = decrypt_file(args.inp, out_path, fernet)
        print(f"Decrypted cells : {n}")
        print(f"Output file     : {out_path}")


if __name__ == "__main__":
    main()
