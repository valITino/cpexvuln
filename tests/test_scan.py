import pathlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scan


@pytest.fixture
def sample_cpe():
    return "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"


def test_run_scan_logs_warning_on_error(monkeypatch, sample_cpe, capsys):
    def fake_fetch(*args, **kwargs):
        raise RuntimeError("network boom")

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    results, updated = scan.run_scan(
        cpes=[sample_cpe],
        state_all={},
        state_key="nvd:test",
        session=object(),
        insecure=False,
        since=datetime.now(timezone.utc) - timedelta(days=1),
    )

    captured = capsys.readouterr()
    assert "network boom" in captured.out
    assert results == []
    assert updated["per_cpe"] == {}


def test_run_scan_collects_latest_and_filters(monkeypatch, sample_cpe):
    now = datetime(2024, 1, 10, tzinfo=timezone.utc)

    def fake_fetch(session, cpe, since, until, insecure=False):
        assert cpe == sample_cpe
        # Vulnerability-Lookup format
        return [
            {
                "id": "CVE-1",
                "Published": "2024-01-01T00:00:00.000Z",
                "last-modified": "2024-01-05T00:00:00.000Z",
                "assigner": "src",
                "cvss-metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 8.1,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "High",
                        }
                    }
                ],
                "summary": "Example vuln",
                "cwe": ["79"],
                "references": [{"url": "https://example", "source": "NVD", "tags": ["Patch"]}],
                "state": "Analyzed",
                "kev": {
                    "dateAdded": "2024-01-06"
                },
                "epss": {
                    "epss": 0.45,
                    "percentile": 0.89
                }
            },
            {
                "id": "CVE-1",
                "Published": "2024-01-01T00:00:00.000Z",
                "last-modified": "2024-01-07T00:00:00.000Z",
                "assigner": "src",
                "cvss-metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 9.0,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "Critical",
                        }
                    }
                ],
                "summary": "Example vuln updated",
                "cwe": ["89"],
                "references": [{"url": "https://example2", "source": "Vendor", "tags": ["Vendor Advisory"]}],
                "state": "Analyzed",
                "kev": {
                    "dateAdded": "2024-01-08"
                },
                "epss": {
                    "epss": 0.75,
                    "percentile": 0.95
                }
            },
        ]

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    since = now - timedelta(days=1)
    state = {}
    results, updated = scan.run_scan(
        cpes=[sample_cpe],
        state_all=state,
        state_key="nvd:test",
        session=object(),
        insecure=False,
        since=since,
        kev_only=True,
    )

    assert len(results) == 1
    record = results[0]
    assert record["cve"] == "CVE-1"
    assert record["severity"] == "Critical"
    assert record["kev"] is True
    assert record["description"] == "Example vuln updated"
    assert record["cwes"] == ["CWE-89"]
    assert record["refs"][0]["url"] == "https://example2"
    assert updated["per_cpe"][sample_cpe]


def test_run_scan_deduplicates_by_latest_modified(monkeypatch, sample_cpe):
    """Test that when multiple entries exist for the same CVE, the latest one is kept."""

    def fake_fetch(session, cpe, since, until, insecure=False):
        # Return two entries for the same CVE with different modification dates
        return [
            {
                "id": "CVE-2024-1234",
                "Published": "2024-01-01T00:00:00.000Z",
                "last-modified": "2024-01-10T00:00:00.000Z",  # Older
                "summary": "Old description",
                "cvss-metrics": [],
            },
            {
                "id": "CVE-2024-1234",
                "Published": "2024-01-01T00:00:00.000Z",
                "last-modified": "2024-01-15T00:00:00.000Z",  # Newer
                "summary": "Updated description",
                "cvss-metrics": [],
            },
        ]

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    results, _ = scan.run_scan(
        cpes=[sample_cpe],
        state_all={},
        state_key="nvd:test",
        session=object(),
        insecure=False,
        since=datetime.now(timezone.utc) - timedelta(days=30),
    )

    # Should only have one result (deduplicated)
    assert len(results) == 1
    assert results[0]["cve"] == "CVE-2024-1234"
    assert results[0]["description"] == "Updated description"
    assert results[0]["lastModified"] == "2024-01-15T00:00:00.000Z"


def test_run_scan_handles_empty_response(monkeypatch, sample_cpe):
    """Test that empty API responses are handled gracefully."""

    def fake_fetch(session, cpe, since, until, insecure=False):
        return []

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    results, updated = scan.run_scan(
        cpes=[sample_cpe],
        state_all={},
        state_key="nvd:test",
        session=object(),
        insecure=False,
        since=datetime.now(timezone.utc) - timedelta(days=1),
    )

    assert results == []
    assert updated["per_cpe"][sample_cpe]  # State should still be updated


def test_run_scan_multiple_cpes(monkeypatch):
    """Test scanning multiple CPEs at once."""
    cpes = [
        "cpe:2.3:a:vendor1:product1:1:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor2:product2:2:*:*:*:*:*:*:*",
    ]

    def fake_fetch(session, cpe, since, until, insecure=False):
        if "vendor1" in cpe:
            return [{"id": "CVE-2024-1111", "last-modified": "2024-01-01T00:00:00.000Z", "cvss-metrics": []}]
        elif "vendor2" in cpe:
            return [{"id": "CVE-2024-2222", "last-modified": "2024-01-02T00:00:00.000Z", "cvss-metrics": []}]
        return []

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    results, updated = scan.run_scan(
        cpes=cpes,
        state_all={},
        state_key="nvd:test",
        session=object(),
        insecure=False,
        since=datetime.now(timezone.utc) - timedelta(days=30),
    )

    assert len(results) == 2
    cve_ids = [r["cve"] for r in results]
    assert "CVE-2024-1111" in cve_ids
    assert "CVE-2024-2222" in cve_ids
    # Both CPEs should be in the state
    assert len(updated["per_cpe"]) == 2
