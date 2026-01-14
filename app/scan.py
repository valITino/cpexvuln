from typing import List, Tuple, Dict

from .utils import now_utc, iso
from .vulnerabilitylookup import (
    fetch_for_cpe,
    extract_cve_id,
    extract_metrics,
    is_kev,
    extract_kev_data,
    extract_epss,
    extract_description,
    extract_cwes,
    extract_references,
    extract_published_date,
    extract_last_modified_date,
)


def run_scan(
    cpes: List[str],
    state_all: dict,
    state_key: str,
    session,
    insecure: bool,
    since,
    kev_only: bool = False,
) -> Tuple[List[dict], dict]:
    """
    Run vulnerability scan for multiple CPE strings.

    Args:
        cpes: List of CPE 2.3 strings to scan
        state_all: Current state dictionary
        state_key: State key for this CPE set
        session: Requests session
        insecure: Skip TLS verification if True
        since: Start datetime for scanning
        kev_only: If True, return only KEV vulnerabilities

    Returns:
        Tuple of (records_list, updated_state_entry)
        state_all[state_key] = {"version": 3, "last_long_rescan": ISO, "per_cpe": {cpe: ISO}}
    """
    now = now_utc()
    entry = state_all.get(state_key) or {}
    per_cpe = dict(entry.get("per_cpe") or {})
    last_long_rescan = entry.get("last_long_rescan")

    all_vulns: Dict[str, dict] = {}
    any_success = False

    for cpe in cpes:
        try:
            vulns = fetch_for_cpe(
                session,
                cpe,
                since,
                now,
                insecure,
            )
            any_success = True
            per_cpe[cpe] = iso(now)
            for item in vulns:
                # Vulnerability-Lookup format: CVE ID at top level or in 'id' field
                cve_id = extract_cve_id(item)
                if not cve_id:
                    continue

                metrics = extract_metrics(item)
                epss_data = extract_epss(item)
                kev_flag = is_kev(item)
                kev_metadata = extract_kev_data(item) if kev_flag else {}

                # Get dates - Vulnerability-Lookup uses different field names
                published = extract_published_date(item)
                last_modified = extract_last_modified_date(item)

                record = {
                    "cve": cve_id,
                    "published": published,
                    "lastModified": last_modified,
                    "sourceIdentifier": item.get("sourceIdentifier") or item.get("assigner"),
                    "kev": kev_flag,
                    "kev_data": kev_metadata,
                    "epss": epss_data.get("score"),
                    "epss_percentile": epss_data.get("percentile"),
                    "metrics": metrics,
                    "severity": metrics.get("baseSeverity") or "None",
                    "score": metrics.get("baseScore"),
                    "refs": extract_references(item),
                    "matched_cpe_query": cpe,
                    "description": extract_description(item),
                    "cwes": extract_cwes(item),
                    "vulnStatus": item.get("vulnStatus") or item.get("state"),
                }
                previous = all_vulns.get(cve_id)
                if not previous or (record["lastModified"] or "") > (previous.get("lastModified") or ""):
                    all_vulns[cve_id] = record
        except Exception as exc:  # pragma: no cover - network edge cases
            print(f"[WARN] request failed for {cpe}: {exc}")

    out_list = sorted(all_vulns.values(), key=lambda value: (value["lastModified"] or value["published"] or ""))

    updated = {"version": 3, "per_cpe": per_cpe}
    if any_success and (now - since).days >= 89:
        updated["last_long_rescan"] = iso(now)
    elif last_long_rescan:
        updated["last_long_rescan"] = last_long_rescan

    if kev_only:
        out_list = [record for record in out_list if record.get("kev")]

    return out_list, updated
