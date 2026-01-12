import pathlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scan_history


def test_calculate_summary():
    """Test summary calculation for CVE records."""
    records = [
        {"severity": "Critical", "kev": True, "epss": 0.75},
        {"severity": "Critical", "kev": False, "epss": 0.55},
        {"severity": "High", "kev": True, "epss": 0.30},
        {"severity": "Medium", "kev": False, "epss": 0.10},
        {"severity": "Low", "kev": False, "epss": None},
    ]

    summary = scan_history.calculate_summary(records)

    assert summary["total"] == 5
    assert summary["critical"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["kev_count"] == 2
    assert summary["epss_high_count"] == 2  # 0.75 and 0.55 >= 0.5


def test_compare_scans():
    """Test scan comparison logic."""
    current_cves = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    previous_cves = ["CVE-2024-0001", "CVE-2024-0004"]

    comparison = scan_history.compare_scans(current_cves, previous_cves)

    assert "CVE-2024-0002" in comparison["new"]
    assert "CVE-2024-0003" in comparison["new"]
    assert "CVE-2024-0004" in comparison["removed"]
    assert "CVE-2024-0001" in comparison["common"]


def test_compare_scans_empty_previous():
    """Test comparison when previous scan is empty."""
    current_cves = ["CVE-2024-0001", "CVE-2024-0002"]
    previous_cves = []

    comparison = scan_history.compare_scans(current_cves, previous_cves)

    assert len(comparison["new"]) == 2
    assert len(comparison["removed"]) == 0
    assert len(comparison["common"]) == 0


def test_compare_scans_all_same():
    """Test comparison when scans are identical."""
    cves = ["CVE-2024-0001", "CVE-2024-0002"]

    comparison = scan_history.compare_scans(cves, cves)

    assert len(comparison["new"]) == 0
    assert len(comparison["removed"]) == 0
    assert len(comparison["common"]) == 2


def test_cleanup_old_scans(monkeypatch):
    """Test that old scans are properly cleaned up."""
    now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(scan_history, "now_utc", lambda: now)

    history = {
        "scans": [
            {"id": "1", "timestamp": "2024-06-10T00:00:00.000Z"},  # 5 days old - keep
            {"id": "2", "timestamp": "2024-01-01T00:00:00.000Z"},  # Very old - remove
            {"id": "3", "timestamp": "2024-06-14T00:00:00.000Z"},  # 1 day old - keep
        ]
    }

    cleaned = scan_history.cleanup_old_scans(history, retention_days=30)

    assert len(cleaned["scans"]) == 2
    scan_ids = [s["id"] for s in cleaned["scans"]]
    assert "1" in scan_ids
    assert "3" in scan_ids
    assert "2" not in scan_ids


def test_get_time_based_filter(monkeypatch):
    """Test filtering CVEs by age."""
    now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(scan_history, "now_utc", lambda: now)

    records = [
        {"cve": "CVE-1", "published": "2024-06-15T06:00:00.000Z"},  # 6 hours old
        {"cve": "CVE-2", "published": "2024-06-14T12:00:00.000Z"},  # 24 hours old
        {"cve": "CVE-3", "published": "2024-06-10T12:00:00.000Z"},  # 5 days old
        {"cve": "CVE-4", "published": None},  # No date - included
    ]

    # Filter to last 12 hours
    filtered = scan_history.get_time_based_filter(records, hours=12)

    assert len(filtered) == 2
    cves = [r["cve"] for r in filtered]
    assert "CVE-1" in cves
    assert "CVE-4" in cves  # No date, so included


def test_calculate_summary_empty():
    """Test summary calculation with empty records."""
    summary = scan_history.calculate_summary([])

    assert summary["total"] == 0
    assert summary["critical"] == 0
    assert summary["kev_count"] == 0
    assert summary["epss_high_count"] == 0
