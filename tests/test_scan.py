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
        api_key=None,
        since=datetime.now(timezone.utc) - timedelta(days=1),
    )

    captured = capsys.readouterr()
    assert "network boom" in captured.out
    assert results == []
    assert updated["per_cpe"] == {}


def test_run_scan_collects_latest_and_filters(monkeypatch, sample_cpe):
    now = datetime(2024, 1, 10, tzinfo=timezone.utc)

    def fake_fetch(session, cpe, since, until, **kwargs):
        assert cpe == sample_cpe
        return [
            {
                "cve": {
                    "id": "CVE-1",
                    "published": "2024-01-01T00:00:00.000Z",
                    "lastModified": "2024-01-05T00:00:00.000Z",
                    "sourceIdentifier": "src",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 8.1,
                                    "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                                "baseSeverity": "High",
                            }
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "Example vuln"}],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [{"url": "https://example", "source": "NVD", "tags": ["Patch"]}],
                    "vulnStatus": "Analyzed",
                    "cisaExploitAdd": "2024-01-06",
                }
            },
            {
                "cve": {
                    "id": "CVE-1",
                    "published": "2024-01-01T00:00:00.000Z",
                    "lastModified": "2024-01-07T00:00:00.000Z",
                    "sourceIdentifier": "src",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 9.0,
                                    "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                                "baseSeverity": "Critical",
                            }
                        ]
                    },
                    "descriptions": [{"lang": "en", "value": "Example vuln updated"}],
                    "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                    "references": [{"url": "https://example2", "source": "Vendor", "tags": ["Vendor Advisory"]}],
                    "vulnStatus": "Analyzed",
                    "cisaExploitAdd": "2024-01-08",
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
        api_key=None,
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
