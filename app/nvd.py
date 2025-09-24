from typing import List, Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from .config import API_BASE, MAX_RANGE_DAYS, DEFAULT_TIMEOUT
from .utils import iso, chunk_windows, has_specific_version

UA = "CPE-Watch/1.2 (+local)"


def build_session(https_proxy=None, http_proxy=None, ca_bundle=None, insecure=False, timeout=DEFAULT_TIMEOUT):
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))

    proxies: Dict[str, str] = {}
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    if proxies:
        session.proxies.update(proxies)

    if ca_bundle:
        session.verify = ca_bundle
    session.timeout = timeout

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session


def _do_get(session: requests.Session, params, insecure: bool, api_key: Optional[str], url: str = API_BASE):
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    verify = False if insecure else getattr(session, "verify", True)
    timeout = getattr(session, "timeout", DEFAULT_TIMEOUT)
    return session.get(url, headers=headers, params=params, verify=verify, timeout=timeout)


def _fetch_window(session, params_base, since, until, insecure, api_key) -> List[dict]:
    results: List[dict] = []
    for start, end in chunk_windows(since, until, MAX_RANGE_DAYS):
        start_index = 0
        while True:
            params = dict(params_base)
            params["lastModStartDate"] = iso(start)
            params["lastModEndDate"] = iso(end)
            params["startIndex"] = start_index

            response = _do_get(session, params, insecure, api_key)
            if response.status_code in (400, 404):
                if "noRejected" in params:
                    retry_params = dict(params)
                    retry_params.pop("noRejected", None)
                    retry_response = _do_get(session, retry_params, insecure, api_key)
                    retry_response.raise_for_status()
                    data = retry_response.json()
                else:
                    response.raise_for_status()
            else:
                response.raise_for_status()
                data = response.json()

            vulnerabilities = data.get("vulnerabilities", []) or []
            results.extend(vulnerabilities)

            total = int(data.get("totalResults", 0))
            per_page = int(data.get("resultsPerPage", 0))
            start_index = int(data.get("startIndex", 0)) + per_page
            if start_index >= total or per_page == 0:
                break
    return results


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "None"
    try:
        value = float(score)
    except Exception:
        return "None"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0.0:
        return "Low"
    return "None"


def _pick_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        series = metrics.get(key)
        if not series:
            continue
        entry = series[0]
        data = entry.get("cvssData", {}) or {}
        score = data.get("baseScore")
        severity = entry.get("baseSeverity") or data.get("baseSeverity") or _severity_from_score(score)
        return {
            "version": data.get("version"),
            "vector": data.get("vectorString"),
            "baseScore": score,
            "baseSeverity": severity,
        }
    return {"version": None, "vector": None, "baseScore": None, "baseSeverity": "None"}


def extract_metrics(vuln) -> Dict[str, Any]:
    metrics = vuln.get("cve", {}).get("metrics", {}) or {}
    return _pick_cvss(metrics)


def extract_description(vuln) -> str:
    descriptions = vuln.get("cve", {}).get("descriptions", []) or []
    for entry in descriptions:
        if (entry.get("lang") or "").lower() == "en":
            value = (entry.get("value") or "").strip()
            if value:
                return value
    for entry in descriptions:
        value = (entry.get("value") or "").strip()
        if value:
            return value
    return ""


def extract_cwes(vuln) -> List[str]:
    found: List[str] = []
    weaknesses = vuln.get("cve", {}).get("weaknesses") or []
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = (description.get("value") or "").strip()
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def extract_references(vuln) -> List[Dict[str, Any]]:
    references = []
    for ref in (vuln.get("cve", {}).get("references") or []):
        references.append(
            {
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags") or [],
            }
        )
    return references


def is_kev(vuln) -> bool:
    cve = vuln.get("cve", {})
    kev_keys = (
        "cisaExploitAdd",
        "cisaActionDue",
        "cisaRequiredAction",
        "cisaVulnerabilityName",
    )
    return any(key in cve for key in kev_keys)


def fetch_for_cpe(
    session: requests.Session,
    cpe: str,
    since,
    until,
    api_key: Optional[str],
    insecure: bool,
    no_rejected: bool = True,
) -> List[dict]:
    """
    Preferred path: virtualMatchString (broad, wildcard-friendly).
    If server responds 400/404, retry without noRejected.
    If still unsupported and CPE has specific version, fall back to cpeName (strict).
    """
    params = {"resultsPerPage": 2000, "virtualMatchString": cpe}
    if no_rejected:
        params["noRejected"] = "true"

    try:
        return _fetch_window(session, params, since, until, insecure, api_key)
    except requests.HTTPError as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if status_code in (400, 404) and has_specific_version(cpe):
            fallback = {"resultsPerPage": 2000, "cpeName": cpe}
            if no_rejected:
                fallback["noRejected"] = "true"
            return _fetch_window(session, fallback, since, until, insecure, api_key)
        raise
