import pathlib
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import nvd


class DummySession:
    def __init__(self):
        self.get_calls = []

    def get(self, url, params=None, headers=None, timeout=None, verify=True):
        self.get_calls.append({
            "url": url,
            "params": params,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        })
        raise RuntimeError('Unexpected call')


def _window():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=1), now


def test_pick_preferred_cvss_prefers_v4():
    metrics = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 7.5,
                    "vectorString": "AV:N/AC:L/...",
                },
                "baseSeverity": "High",
            }
        ],
        "cvssMetricV4": [
            {
                "cvssData": {
                    "version": "4.0",
                    "baseScore": 8.3,
                    "vectorString": "CVSS:4.0/...",
                },
                "baseSeverity": "Critical",
            }
        ],
    }
    result = nvd.pick_preferred_cvss(metrics)
    assert result["version"] == "4.0"
    assert result["baseScore"] == 8.3
    assert result["baseSeverity"] == "Critical"


def test_fetch_for_cpe_paginates(monkeypatch):
    since, until = _window()
    session = DummySession()
    responses = [
        {
            "vulnerabilities": [
                {"cve": {"id": "CVE-1"}},
                {"cve": {"id": "CVE-2"}},
            ],
            "totalResults": 3,
            "resultsPerPage": 2,
            "startIndex": 0,
        },
        {
            "vulnerabilities": [
                {"cve": {"id": "CVE-3"}},
            ],
            "totalResults": 3,
            "resultsPerPage": 2,
            "startIndex": 2,
        },
    ]

    def fake_request(session_obj, url, params, **kwargs):
        assert params["startIndex"] in (0, 2)
        return responses.pop(0)

    monkeypatch.setattr(nvd, "_request_json", fake_request)
    items = nvd.fetch_for_cpe(
        session,
        "cpe:2.3:a:test:prod:1:*:*:*:*:*:*:*",
        since,
        until,
        api_key=None,
        insecure=False,
    )
    assert len(items) == 3


def test_fetch_for_cpe_falls_back_to_cpe_name(monkeypatch):
    since, until = _window()
    session = DummySession()
    params_seen = []

    error = requests.HTTPError(response=SimpleNamespace(status_code=400))

    def fake_request(session_obj, url, params, **kwargs):
        params_seen.append(dict(params))
        if "virtualMatchString" in params:
            raise error
        return {
            "vulnerabilities": [],
            "totalResults": 0,
            "resultsPerPage": 0,
            "startIndex": params.get("startIndex", 0),
        }

    monkeypatch.setattr(nvd, "_request_json", fake_request)
    result = nvd.fetch_for_cpe(
        session,
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        since,
        until,
        api_key=None,
        insecure=False,
    )
    assert result == []
    assert any("cpeName" in call for call in params_seen)


def test_request_json_ssl_error(monkeypatch):
    session = DummySession()

    def raise_ssl(url, params=None, headers=None, timeout=None, verify=True):
        raise requests.exceptions.SSLError("bad cert")

    session.get = raise_ssl  # type: ignore[method-assign]
    sleeps = []
    monkeypatch.setattr(nvd.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(requests.exceptions.SSLError) as excinfo:
        nvd._request_json(session, "https://example", {}, insecure=False, api_key=None)

    assert "TLS handshake" in str(excinfo.value)
    assert sleeps == []
