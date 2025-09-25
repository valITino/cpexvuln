from datetime import datetime, timezone

import pytest

from app import scan


@pytest.fixture
def sample_cpe():
    return "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"


def test_run_scan_collects_issues(monkeypatch, sample_cpe):
    """run_scan should surface recoverable errors as issue entries."""

    def fake_fetch(*args, **kwargs):
        raise RuntimeError("network boom")

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    results, updated, issues = scan.run_scan(
        cpes=[sample_cpe],
        state_all={},
        state_key="nvd:test",
        session=object(),
        insecure=False,
        api_key=None,
        since=datetime.now(timezone.utc),
    )

    assert results == []
    assert isinstance(updated, dict)
    assert issues and issues[0]["cpe"] == sample_cpe
    assert issues[0]["kind"] == "unexpected_error"
    assert "network boom" in issues[0]["message"]


def test_run_scan_uses_cached_results_on_failure(monkeypatch, sample_cpe):
    cached_payload = [{"id": "CVE-1234", "cvssScore": 7.2, "matchedCPE": [sample_cpe]}]

    def fake_fetch(*args, **kwargs):
        raise RuntimeError("api unreachable")

    monkeypatch.setattr(scan, "fetch_for_cpe", fake_fetch)

    state = {
        "nvd:test": {
            "per_cpe": {sample_cpe: "2025-09-01T00:00:00Z"},
            "last_results": cached_payload,
            "last_success": "2025-09-01T00:00:00Z",
        }
    }

    results, updated, issues = scan.run_scan(
        cpes=[sample_cpe],
        state_all=state,
        state_key="nvd:test",
        session=object(),
        insecure=False,
        api_key=None,
        since=datetime.now(timezone.utc),
    )

    assert results == cached_payload
    assert results is not cached_payload
    assert updated.get("last_results") == cached_payload
    assert any(issue.get("kind") == "cached_results" for issue in issues)
