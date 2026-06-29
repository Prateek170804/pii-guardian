"""Classification engine.

Combines name + value signals into a confidence score, maps to a sensitivity tier,
and decides the masking behavior. Output records are the single source of truth that
the SQL generator consumes. No raw sample values are ever included.
"""
from dataclasses import dataclass, field, asdict

from .ingest import Column
from .detectors import NameDetector, detect_values, name_hint


@dataclass
class Classification:
    fqcn: str
    database: str
    schema: str
    table: str
    column: str
    data_type: str
    type_group: str
    category: str | None
    sensitivity: str | None
    confidence: float
    decision: str                       # auto | review | ignore
    mask_behavior: str | None           # behavior key for sqlgen, or None
    signals: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class Classifier:
    def __init__(self, cde_dictionary: dict, taxonomy: dict, masking_rules: dict):
        self.name_detector = NameDetector(cde_dictionary, taxonomy.get("strengths", {}))
        self.sensitivity_by_category = taxonomy.get("sensitivity_by_category", {})
        self.regulation_by_category = taxonomy.get("regulation_by_category", {})
        thr = taxonomy.get("thresholds", {})
        self.high = thr.get("high", 0.80)
        self.low = thr.get("low", 0.45)
        w = taxonomy.get("weights", {})
        self.w_name = w.get("name", 0.5)
        self.w_value = w.get("value", 0.5)
        self.name_only_cap = w.get("name_only_cap", 0.90)
        self.value_only_cap = w.get("value_only_cap", 0.85)
        self.hint_behavior = masking_rules.get("hint_behavior", {})
        self.category_type_default = masking_rules.get("category_type_default", {})

    # -- regulatory dimension -----------------------------------------------
    def regulations(self, category, value_detector=None, column_name=None) -> list:
        """Regulatory regimes a category implicates. PCI is added only for
        payment-card (PAN) data, identified by the card value-detector or a card
        column-name hint."""
        if not category:
            return []
        regs = list(self.regulation_by_category.get(category, []))
        if (value_detector == "card" or name_hint(column_name or "") == "card") \
                and "PCI" not in regs:
            regs.append("PCI")
        return regs

    # -- confidence + category fusion ---------------------------------------
    def _score(self, name_sig, value_sig):
        """Return (confidence, category) from optional name/value signals."""
        if name_sig and value_sig:
            conf = self.w_name * name_sig["signal"] + self.w_value * value_sig["ratio"]
            # Category: a strong, specific name match is a more reliable category
            # signal than a generic value-format guess, so it wins. Otherwise take
            # whichever signal is stronger.
            if name_sig["strength"] == "strong":
                category = name_sig["category"]
            else:
                category = (name_sig["category"] if name_sig["signal"] >= value_sig["ratio"]
                            else value_sig["category"])
            return min(conf, 1.0), category
        if name_sig:
            return min(name_sig["signal"], self.name_only_cap), name_sig["category"]
        if value_sig:
            # Value-only: weight by the detector's specificity so ambiguous numeric
            # formats (bare ZIP-length, bare date/SSN) don't reach auto on their own.
            spec = value_sig.get("specificity", 1.0)
            return min(value_sig["ratio"] * spec, self.value_only_cap), value_sig["category"]
        return 0.0, None

    # -- masking behavior selection -----------------------------------------
    def _behavior(self, column: Column, category, name_sig, value_sig):
        # 1) precise hint from value detector (only if it agrees with the chosen
        #    category), then from the column name
        hint = None
        if (value_sig and value_sig["detector"] in self.hint_behavior
                and value_sig["category"] == category):
            hint = value_sig["detector"]
        if hint is None:
            nh = name_hint(column.column)
            if nh in self.hint_behavior:
                hint = nh
        if hint:
            return self.hint_behavior[hint]
        # 2) fallback: full mask by category + data-type group
        return self.category_type_default.get(category, {}).get(column.type_group)

    # -- main ---------------------------------------------------------------
    def classify(self, column: Column, samples: list[str] | None) -> Classification:
        name_sig = self.name_detector.detect(column.column)
        value_sig = detect_values(samples) if samples else None

        confidence, category = self._score(name_sig, value_sig)
        sensitivity = self.sensitivity_by_category.get(category) if category else None

        if confidence >= self.high and category:
            decision = "auto"
        elif confidence >= self.low and category:
            decision = "review"
        else:
            decision = "ignore"

        behavior = None
        if decision == "auto":
            behavior = self._behavior(column, category, name_sig, value_sig)
            if behavior is None:
                # maskable type unknown (e.g. BOOLEAN/OTHER) -> needs human handling
                decision = "review"

        signals = {}
        if name_sig:
            signals["name"] = {"category": name_sig["category"], "strength": name_sig["strength"],
                               "signal": name_sig["signal"], "pattern": name_sig["pattern"]}
        if value_sig:
            # safe: format label + ratio + count only, never raw values
            signals["value"] = value_sig

        return Classification(
            fqcn=column.fqcn, database=column.database, schema=column.schema,
            table=column.table, column=column.column, data_type=column.data_type,
            type_group=column.type_group, category=category, sensitivity=sensitivity,
            confidence=round(confidence, 3), decision=decision,
            mask_behavior=behavior, signals=signals,
        )


def classify_all(columns, samples_map, cde_dictionary, taxonomy, masking_rules):
    clf = Classifier(cde_dictionary, taxonomy, masking_rules)
    return [clf.classify(c, samples_map.get(c.fqcn)) for c in columns]
