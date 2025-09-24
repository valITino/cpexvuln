import pathlib
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import nvd


def _window():
    now = datetime.now(timezone.utc)
    return now - timedelta(days=1), now


def test_extract_metrics_prefers_v4():
    metrics = {
        "cve": {
            "metrics": {
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
        }
    }
    result = nvd.extract_metrics(metrics)
    assert result["version"] == "4.0"
    assert result["baseScore"] == 8.3
    assert result["baseSeverity"] == "Critical"


def test_fetch_for_cpe_falls_back_to_cpe_name(monkeypatch):
    since, until = _window()
    params_seen = []

    def fake_fetch(session, params_base, *args, **kwargs):
        params_seen.append(dict(params_base))
        if "virtualMatchString" in params_base:
            raise requests.HTTPError(response=SimpleNamespace(status_code=400))
        return []

    monkeypatch.setattr(nvd, "_fetch_window", fake_fetch)
    result = nvd.fetch_for_cpe(
        session=object(),
        cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        since=since,
        until=until,
        api_key=None,
        insecure=False,
        no_rejected=True,
    )
    assert result == []
    assert any("cpeName" in params for params in params_seen)


def test_fetch_window_retries_without_no_rejected(monkeypatch):
    since, until = _window()
    calls = []

    class FakeResponse:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload
            self._raised = False

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(response=self)

        def json(self):
            return self._payload

    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-1"}},
            {"cve": {"id": "CVE-2"}},
        ],
        "totalResults": 2,
        "resultsPerPage": 2,
        "startIndex": 0,
    }

    def fake_get(session, params, insecure, api_key):
        calls.append(dict(params))
        if len(calls) == 1:
            return FakeResponse(400, payload)
        return FakeResponse(200, payload)

    monkeypatch.setattr(nvd, "_do_get", fake_get)
    results = nvd._fetch_window(object(), {"resultsPerPage": 2, "noRejected": "true"}, since, until, False, None)
    assert len(results) == 2
    assert calls[0].get("noRejected") == "true"
    assert "noRejected" not in calls[1]


def test_fetch_window_paginates(monkeypatch):
    since, until = _window()
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

    class Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def fake_get(session, params, insecure, api_key):
        assert params["startIndex"] in (0, 2)
        return Resp(responses.pop(0))

    monkeypatch.setattr(nvd, "_do_get", fake_get)
    items = nvd._fetch_window(object(), {"resultsPerPage": 2}, since, until, False, None)
    assert len(items) == 3
