"""Ingest a Snowflake INFORMATION_SCHEMA.COLUMNS-style CSV into a normalized inventory."""
import csv
from dataclasses import dataclass, asdict


# Map raw Snowflake data types to coarse groups used for masking-policy selection.
_TYPE_GROUPS = {
    "STRING": {"VARCHAR", "CHAR", "CHARACTER", "STRING", "TEXT", "NVARCHAR", "NCHAR"},
    "NUMBER": {"NUMBER", "DECIMAL", "NUMERIC", "INT", "INTEGER", "BIGINT", "SMALLINT",
               "TINYINT", "BYTEINT", "FLOAT", "FLOAT4", "FLOAT8", "DOUBLE", "REAL"},
    "DATE":   {"DATE", "DATETIME", "TIME", "TIMESTAMP", "TIMESTAMP_NTZ",
               "TIMESTAMP_LTZ", "TIMESTAMP_TZ"},
}


def type_group(data_type: str) -> str:
    dt = (data_type or "").strip().upper()
    # strip precision/scale e.g. NUMBER(10,2) -> NUMBER
    base = dt.split("(")[0].strip()
    for group, members in _TYPE_GROUPS.items():
        if base in members:
            return group
    return "OTHER"


@dataclass
class Column:
    database: str
    schema: str
    table: str
    column: str
    data_type: str
    type_group: str
    comment: str = ""

    @property
    def fqcn(self) -> str:
        """Fully-qualified column name."""
        return f"{self.database}.{self.schema}.{self.table}.{self.column}"

    @property
    def fqtn(self) -> str:
        """Fully-qualified table name."""
        return f"{self.database}.{self.schema}.{self.table}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fqcn"] = self.fqcn
        return d


def load_inventory(csv_path: str) -> list[Column]:
    """Read the schema CSV and return a list of Column records."""
    cols: list[Column] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data_type = row.get("DATA_TYPE", "")
            cols.append(Column(
                database=row.get("TABLE_CATALOG", "").strip(),
                schema=row.get("TABLE_SCHEMA", "").strip(),
                table=row.get("TABLE_NAME", "").strip(),
                column=row.get("COLUMN_NAME", "").strip(),
                data_type=data_type.strip(),
                type_group=type_group(data_type),
                comment=(row.get("COMMENT") or "").strip(),
            ))
    return cols
