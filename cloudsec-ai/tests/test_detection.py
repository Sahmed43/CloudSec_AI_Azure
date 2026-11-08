from pathlib import Path
import pytest
from cloudsec.detect import detect
from cloudsec.ingest import load_events
from cloudsec.models import Event

DATA = Path(__file__).resolve().parents[1] / "data" / "synthetic_events.csv"

def test_demo_detects_three_rule_types():
    findings = detect(load_events(DATA))
    assert {f.rule_id for f in findings} == {"AUTH-001", "AUTH-002", "PRIV-001"}
    assert any(f.severity == "high" for f in findings)

def test_empty():
    assert detect([]) == []

def test_no_false_alarm_for_four_failures():
    events = [Event(f"2026-01-01T00:0{i}:00Z", "u", "1.2.3.4", "login", "failure", "app", "US") for i in range(4)]
    assert detect(events) == []

def test_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone"):
        detect([Event("2026-01-01T00:00:00", "u", "ip", "login", "failure", "r", "US")])

def test_rejects_missing_columns(tmp_path):
    file = tmp_path / "bad.csv"
    file.write_text("user,ip\nu,1.2.3.4\n")
    with pytest.raises(ValueError, match="requires columns"):
        load_events(file)
