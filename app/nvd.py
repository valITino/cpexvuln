"""NVD API helpers (CVE + CPE products).
Drop-in replacement with:
- Robust JSON handling (tolerates top-level arrays and odd shapes)
- Safer pagination across date windows
- Clear backoff and error messages
- Helper extractors used by scan.py
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, Iterator, List, Optional

import requests
from requests.adapters import HTTPAdapter
import urllib3

from .config import (
    CVE_API_BASE,
    CPE_API_BASE,
    DEFAULT_TIMEOUT,
    MAX_CPE_PAGE_SIZE,
    MAX_CVE_PAGE_SIZE,
    MAX_RANGE_DAYS,
    MAX_RETRY_DELAY,
)
from .utils import chunk_windows, has_specific_version, iso

UA = "CPE-Watch/2.0 (+local)"
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 6
_RNG = random.SystemRandom()


def build_session(
    https_proxy: Optional[str] = None,
    http_proxy: Optional[str] = None,
    ca_bundle: Optional[str] = None,
    insecure: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Session:
    """Create a configured ``requests.Session`` for NVD calls."""

    session = requests.Session()
    adapter = HTTPAdapter(max_retries=0)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    proxies: Dict[str, str] = {}
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    if proxies:
        session.proxies.update(proxies)

    if ca_bundle:
        session.verify = ca_bundle

    session.timeout = timeout or DEFAULT_TIMEOUT

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session


def _session_timeout(session: requests.Session) -> int:
    try:
        value = int(getattr(session, "timeout", DEFAULT_TIMEOUT))
        return value if value > 0 else DEFAULT_TIMEOUT
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


def _headers(api_key: Optional[str]) -> Dict[str, str]:
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _request_json(
    session: requests.Session,
    url: str,
    params: Dict[str, Any],
    *,
    insecure: bool,
    api_key: Optional[str],
) -> Dict[str, Any]:
    """Perform a GET request with retry/backoff and return decoded JSON as a dict.
    If the API returns a top-level array, coerce it to a dict with the expected key.
    """

    delay = 1.0
    last_exc: Optional[Exception] = None
    for _attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = session.get(
                url,
                params=params,
                headers=_headers(api_key),
                timeout=_session_timeout(session),
                verify=False if insecure else getattr(session, "verify", True),
            )

            # Treat only 5xx as retryable; 4xx bubble up to caller
            if response.status_code >= 500:
                last_exc = requests.HTTPError(f"{response.status_code} from NVD", response=response)
            else:
                try:
                    payload = response.json()
                except ValueError:
                    last_exc = requests.HTTPError("Invalid JSON from NVD", response=response)
                else:
                    # Coerce top-level arrays to the shape our callers expect
                    if isinstance(payload, list):
                        # Heuristic based on endpoint
                        if "/cves/" in url:
                            return {
                                "vulnerabilities": payload,
                                "totalResults": len(payload),
                                "resultsPerPage": len(payload),
                                "startIndex": params.get("startIndex", 0),
                            }
                        if "/cpes/" in url:
                            return {
                                "products": payload,
                                "totalResults": len(payload),
                                "resultsPerPage": len(payload),
                                "startIndex": params.get("startIndex", 0),
                            }
                        # Fallback generic wrapper
                        return {"items": payload, "totalResults": len(payload)}

                    if not isinstance(payload, dict):
                        # Final guard: never return a non-dict
                        return {}

                    return payload

        except requests.exceptions.SSLError as exc:
            raise requests.exceptions.SSLError(
                "TLS handshake with the NVD API failed. "
                "Provide a CA bundle (--ca-bundle) or enable insecure mode (--insecure)."
            ) from exc
        except requests.RequestException as exc:
            last_exc = exc  # network-level issues → backoff

        # jittered exponential backoff
        wait = min(delay + _RNG.uniform(0, delay), MAX_RETRY_DELAY)
        time.sleep(wait)
        delay = min(delay * 2, MAX_RETRY_DELAY)

    if last_exc:
        raise last_exc
    raise requests.HTTPError("NVD request failed after retries")


def _fetch_cve_window(
    session: requests.Session,
    params_base: Dict[str, Any],
    since,
    until,
    *,
    insecure: bool,
    api_key: Optional[str],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    base = dict(params_base)
    base.setdefault("resultsPerPage", MAX_CVE_PAGE_SIZE)
    for window_start, window_end in chunk_windows(since, until, MAX_RANGE_DAYS):
        start_index = 0
        while True:
            params = dict(base)
            params["lastModStartDate"] = iso(window_start)
            params["lastModEndDate"] = iso(window_end)
            params["startIndex"] = start_index
            data = _request_json(
                session, CVE_API_BASE, params, insecure=insecure, api_key=api_key
            ) or {}

            # Be tolerant if API hands us an unexpected shape
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", []) or data.get("items", []) or []
            elif isinstance(data, list):
                vulns = data
            else:
                vulns = []

            results.extend(vulns)

            total = int((isinstance(data, dict) and data.get("totalResults")) or 0)
            rpp = int(
                (isinstance(data, dict) and data.get("resultsPerPage"))
                or (len(vulns) or base["resultsPerPage"])  # fallback to base page size
            )
            current_index = int((isinstance(data, dict) and data.get("startIndex")) or start_index)

            if not vulns or (total and current_index + rpp >= total):
                break
            start_index += rpp
    return results


def fetch_for_cpe(
    session: requests.Session,
    cpe: str,
    since,
    until,
    *,
    api_key: Optional[str],
    insecure: bool,
    no_rejected: bool = True,
    is_vulnerable: bool = False,
    extra_params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Fetch CVEs for a CPE with automatic fallback handling."""

    params = {"resultsPerPage": MAX_CVE_PAGE_SIZE}
    params.update(extra_params or {})

    if is_vulnerable:
        params["cpeName"] = cpe
        params["isVulnerable"] = "true"
    else:
        params["virtualMatchString"] = cpe

    if no_rejected:
        params["noRejected"] = "true"

    try:
        return _fetch_cve_window(
            session,
            params,
            since,
            until,
            insecure=insecure,
            api_key=api_key,
        )
    except requests.HTTPError as exc:
        status = getattr(exc, "response", None)
        status_code = getattr(status, "status_code", None)
        if status_code in (400, 404):
            # Retry without noRejected (some queries 400 on NVD)
            params_no_rejected = dict(params)
            params_no_rejected.pop("noRejected", None)
            if params_no_rejected != params:
                try:
                    return _fetch_cve_window(
                        session,
                        params_no_rejected,
                        since,
                        until,
                        insecure=insecure,
                        api_key=api_key,
                    )
                except requests.HTTPError:
                    pass
            # Fallback to strict cpeName if possible
            if not is_vulnerable and has_specific_version(cpe):
                params_strict = dict(params)
                params_strict.pop("virtualMatchString", None)
                params_strict["cpeName"] = cpe
                return _fetch_cve_window(
                    session,
                    params_strict,
                    since,
                    until,
                    insecure=insecure,
                    api_key=api_key,
                )
        raise


def iter_cpe_products(
    session: requests.Session,
    *,
    api_key: Optional[str],
    insecure: bool,
    params: Dict[str, Any],
) -> Iterator[Dict[str, Any]]:
    """Iterate over results from the CPE products API."""

    base = dict(params)
    rpp = min(MAX_CPE_PAGE_SIZE, int(base.get("resultsPerPage", MAX_CPE_PAGE_SIZE)))
    if rpp <= 0:
        rpp = MAX_CPE_PAGE_SIZE
    base.setdefault("resultsPerPage", rpp)

    start_index = 0
    while True:
        base["startIndex"] = start_index
        data = _request_json(session, CPE_API_BASE, base, insecure=insecure, api_key=api_key) or {}
        if isinstance(data, dict):
            products = data.get("products", []) or data.get("items", []) or []
        elif isinstance(data, list):
            products = data
        else:
            products = []

        for item in products:
            if isinstance(item, dict):
                yield item

        total = int((isinstance(data, dict) and data.get("totalResults")) or 0)
        rpp = int((isinstance(data, dict) and data.get("resultsPerPage")) or (len(products) or base["resultsPerPage"]))
        if not products or (total and start_index + rpp >= total):
            break
        start_index += rpp


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "None"
    try:
        value = float(score)
    except (TypeError, ValueError):
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


def pick_preferred_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        series = metrics.get(key)
        if not series:
            continue
        data = series[0].get("cvssData", {}) if isinstance(series, list) else {}
        score = data.get("baseScore")
        severity = series[0].get("baseSeverity") if isinstance(series, list) else None
        return {
            "version": data.get("version"),
            "vectorString": data.get("vectorString"),
            "baseScore": score,
            "baseSeverity": severity or _severity_from_score(score),
        }
    return {
        "version": None,
        "vectorString": None,
        "baseScore": None,
        "baseSeverity": "None",
    }


def extract_description(vuln: Dict[str, Any]) -> str:
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


def extract_cwes(vuln: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    weaknesses = vuln.get("cve", {}).get("weaknesses") or []
    for weak in weaknesses:
        for desc in weak.get("description") or []:
            value = (desc.get("value") or "").strip()
            if value.startswith("CWE-") and value not in out:
                out.append(value)
    return out


def extract_references(vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = vuln.get("cve", {}).get("references") or []
    items: List[Dict[str, Any]] = []
    for ref in refs:
        items.append(
            {
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags") or [],
            }
        )
    return items


def extract_affected_cpes(vuln: Dict[str, Any]) -> List[str]:
    cfg = vuln.get("cve", {}).get("configurations") or {}
    acc: List[str] = []
    nodes = cfg.get("nodes") or []
    for node in nodes:
        matches = node.get("cpeMatch") or []
        for match in matches:
            for key in ("criteria", "cpeName"):
                val = match.get(key)
                if val and val not in acc:
                    acc.append(val)
    return acc


def is_kev(vuln: Dict[str, Any]) -> bool:
    cve = vuln.get("cve", {})
    return any(
        key in cve
        for key in (
            "cisaExploitAdd",
            "cisaActionDue",
            "cisaRequiredAction",
            "cisaVulnerabilityName",
        )
    )
