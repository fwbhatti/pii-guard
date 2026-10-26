"""Scan SQLite databases for PII and create sanitized copies."""

import shutil
import sqlite3
from collections import Counter

from . import llm
from .detectors import column_hint, find_pii
from .masking import STRATEGIES, mask_text


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    return [r[0] for r in rows]


def detect(value, use_llm: bool) -> list[dict]:
    """Rules first; the LLM adds what rules miss in free text (names, addresses)."""
    findings = find_pii(value)
    if use_llm and isinstance(value, str) and " " in value:
        seen = {f["value"] for f in findings}
        findings += [f for f in llm.find_pii_llm(value) if f["value"] not in seen]
    return findings


def scan(db_path: str, use_llm: bool = False, sample_size: int = 200) -> dict:
    """Report which columns contain which kinds of PII."""
    conn = sqlite3.connect(db_path)
    report = {"database": db_path, "llm_used": use_llm, "tables": {}}
    for table in list_tables(conn):
        cursor = conn.execute(f'SELECT * FROM "{table}" LIMIT ?', (sample_size,))
        columns = [d[0] for d in cursor.description]
        rows = cursor.fetchall()
        table_report = {}
        for idx, col in enumerate(columns):
            counts = Counter()
            for row in rows:
                for f in detect(row[idx], use_llm):
                    counts[f["type"]] += 1
            hint = column_hint(col)
            if counts or hint:
                table_report[col] = {
                    "pii_types": sorted(set(counts) | ({hint} if hint else set())),
                    "matches_in_sample": sum(counts.values()),
                    "rows_sampled": len(rows),
                }
        report["tables"][table] = table_report
    conn.close()
    return report


def sanitize(db_path: str, out_path: str, strategy: str = "synthetic", use_llm: bool = False) -> int:
    """Copy the database and mask PII in the copy. Returns the number of values changed."""
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {list(STRATEGIES)}")
    shutil.copyfile(db_path, out_path)
    conn = sqlite3.connect(out_path)
    changed = 0
    for table in list_tables(conn):
        cursor = conn.execute(f'SELECT rowid, * FROM "{table}"')
        columns = [d[0] for d in cursor.description][1:]
        for row in cursor.fetchall():
            rowid, values = row[0], row[1:]
            for col, value in zip(columns, values):
                if not isinstance(value, str):
                    continue
                findings = detect(value, use_llm)
                hint = column_hint(col)
                if not findings and hint:
                    findings = [{"type": hint, "value": value}]
                if findings:
                    new_value = mask_text(value, findings, strategy)
                    if new_value != value:
                        conn.execute(f'UPDATE "{table}" SET "{col}" = ? WHERE rowid = ?', (new_value, rowid))
                        changed += 1
    conn.commit()
    conn.close()
    return changed
