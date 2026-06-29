"""Detect schema changes vs the previous run's snapshot.

Used for the continuous loop: only newly arrived columns need re-classification
and incremental protection.
"""
import json
import os


def load_snapshot(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return set(json.load(f).get("columns", []))


def save_snapshot(path: str, columns) -> None:
    fqcns = sorted({c.fqcn for c in columns})
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"columns": fqcns}, f, indent=2)


def diff(prev: set[str], columns) -> dict:
    current = {c.fqcn for c in columns}
    return {
        "added": sorted(current - prev),
        "removed": sorted(prev - current),
        "is_baseline": len(prev) == 0,
    }
