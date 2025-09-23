import time
from typing import List, Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from .config import API_BASE, MAX_RANGE_DAYS, DEFAULT_TIMEOUT
from .utils import iso, chunk_windows, has_specific_version

UA = "CPE-Watch/1.2 (+local)"

def build_session(https_proxy=None, http_proxy=None, ca_bundle=None, insecure=False, timeout=DEFAULT_TIMEOUT):
    s = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))

    proxies = {}
    if http_proxy:  proxies["http"]  = http_proxy
    if https_proxy: proxies["https"] = https_proxy
    if proxies:
        s.proxies.update(proxies)

    if ca_bundle:
        s.verify = ca_bundle
    s.timeout = timeout

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return s

def _do_get(session: requests.Session, params, insecure: bool, api_key: Optional[str]):
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    verify = False if insecure else getattr(session, "verify", True)
    timeout = getattr(session, "timeout", DEFAULT_TIMEOUT)
    return session.get(API_BASE, headers=headers, params=params, verify=verify, timeout=timeout)

def _fetch_window(session, params_base, since, until, insecure, api_key) -> List[dict]:
    results = []
    for s, e in chunk_windows(since, until, MAX_RANGE_DAYS):
        start_index = 0
        while True:
            params = dict(params_base)
            params["lastModStartDate"] = iso(s)
            params["lastModEndDate"]   = iso(e)
            params["startIndex"]       = start_index

            r = _do_get(session, params, insecure, api_key)
            # Handle edge 400/404 (seen with some proxies or param mixes)
            if r.status_code in (400, 404):
                if "noRejected" in params:
                    params_nr = dict(params); params_nr.pop("noRejected", None)
                    r2 = _do_get(session, params_nr, insecure, api_key)
                    r2.raise_for_status()
                    data = r2.json()
                else:
                    r.raise_for_status()
            else:
                r.raise_for_status()
                data = r.json()

            vulns = data.get("vulnerabilities", [])
            results.extend(vulns)

            total = int(data.get("totalResults", 0))
            rpp   = int(data.get("resultsPerPage", 0))
            start_index = int(data.get("startIndex", 0)) + rpp
            if start_index >= total or rpp == 0:
                break
    return results

def _severity_from_score(score: Optional[float]) -> str:
    if score is None: return "None"
    try:
        s = float(score)
    except Exception:
        return "None"
    if s >= 9.0: return "Critical"
    if s >= 7.0: return "High"
    if s >= 4.0: return "Medium"
    if s >  0.0: return "Low"
    return "None"

def _pick_cvss(metrics: Dict[str, Any]) -> Dict[str, Any]:
    # prefer v4, then v3.1, then v3.0, then v2
    for key in ("cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            m = arr[0]
            data = m.get("cvssData", {}) or {}
            score = data.get("baseScore")
            sev = m.get("baseSeverity") or data.get("baseSeverity") or _severity_from_score(score)
            return {
                "version": data.get("version"),
                "vector": data.get("vectorString"),
                "baseScore": score,
                "baseSeverity": sev,
            }
    return {"version": None, "vector": None, "baseScore": None, "baseSeverity": "None"}

def extract_metrics(v) -> Dict:
    m = v.get("cve", {}).get("metrics", {}) or {}
    return _pick_cvss(m)

def extract_description(v) -> str:
    descs = v.get("cve", {}).get("descriptions", []) or []
    for d in descs:
        if (d.get("lang") or "").lower() == "en":
            val = (d.get("value") or "").strip()
            if val: return val
    for d in descs:  # fallback any
        val = (d.get("value") or "").strip()
        if val: return val
    return ""

def extract_cwes(v) -> List[str]:
    out = []
    for w in (v.get("cve", {}).get("weaknesses") or []):
        for d in (w.get("description") or []):
            val = (d.get("value") or "").strip()
            if val.startswith("CWE-") and val not in out:
                out.append(val)
    return out

def extract_references(v) -> List[Dict[str, Any]]:
    out = []
    for r in (v.get("cve", {}).get("references") or []):
        out.append({
            "url": r.get("url"),
            "source": r.get("source"),
            "tags": r.get("tags") or [],
        })
    return out

def is_kev(v) -> bool:
    cve = v.get("cve", {})
    return any(x in cve for x in ("cisaExploitAdd","cisaActionDue","cisaRequiredAction","cisaVulnerabilityName"))

def fetch_for_cpe(session: requests.Session, cpe: str, since, until,
                  api_key: Optional[str], insecure: bool, no_rejected: bool=True) -> List[dict]:
    """
    Preferred path: virtualMatchString (broad, wildcard-friendly).
    If server responds 400/404, retry without noRejected.
    If still unsupported and CPE has specific version, fall back to cpeName (strict).
    """
    base = {"resultsPerPage": 2000, "virtualMatchString": cpe}
    if no_rejected:
        base["noRejected"] = "true"

    try:
        return _fetch_window(session, base, since, until, insecure, api_key)
    except requests.HTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status in (400, 404) and has_specific_version(cpe):
            base2 = {"resultsPerPage": 2000, "cpeName": cpe}
            if no_rejected:
                base2["noRejected"] = "true"
            return _fetch_window(session, base2, since, until, insecure, api_key)
        raise
