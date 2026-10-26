import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from make_sample_db import build
from pii_guard.detectors import column_hint, find_pii, luhn_valid
from pii_guard.llm import parse_response
from pii_guard.masking import mask_text, partial
from pii_guard.scanner import sanitize, scan


def test_finds_email_phone_ssn():
    types = {f["type"] for f in find_pii("Email a@b.com, call 703-555-1234, SSN 123-45-6789")}
    assert {"EMAIL", "PHONE", "SSN"} <= types


def test_luhn_rejects_random_numbers():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("1234 5678 9012 3456")


def test_column_hints():
    assert column_hint("customer_email") == "EMAIL"
    assert column_hint("plan") is None


def test_partial_mask_keeps_last_four():
    assert partial("123-45-6789", "SSN") == "*******6789"


def test_mask_text_redacts():
    text = "reach me at a@b.com"
    assert mask_text(text, find_pii(text), "redact") == "reach me at [EMAIL]"


def test_parse_llm_response():
    raw = 'Sure: [{"type": "NAME", "value": "Jane Doe"}] done'
    assert parse_response(raw) == [{"type": "NAME", "value": "Jane Doe"}]
    assert parse_response("no json here") == []


def test_scan_and_sanitize(tmp_path):
    db = tmp_path / "sample.db"
    build(str(db), n=20)
    report = scan(str(db))
    assert "EMAIL" in report["tables"]["customers"]["email"]["pii_types"]
    assert "plan" not in report["tables"]["customers"]

    out = tmp_path / "clean.db"
    changed = sanitize(str(db), str(out), strategy="redact")
    assert changed > 0
    conn = sqlite3.connect(out)
    emails = [r[0] for r in conn.execute("SELECT email FROM customers")]
    conn.close()
    assert all(e == "[EMAIL]" for e in emails)
