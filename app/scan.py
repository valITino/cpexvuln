from typing import List, Tuple, Optional, Dict

from .utils import now_utc, iso
from .nvd import fetch_for_cpe, extract_metrics, is_kev, extract_description, extract_cwes, extract_references


def run_scan(
    cpes: List[str],
    state_all: dict,
    state_key: str,
    session,
    insecure: bool,
    api_key: Optional[str],
    since,
    no_rejected: bool = True,
    kev_only: bool = False,
) -> Tuple[List[dict], dict]:
    """
    Returns (records_list, updated_state_entry)
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
                api_key=api_key,
                insecure=insecure,
                no_rejected=no_rejected,
            )
            any_success = True
            per_cpe[cpe] = iso(now)
            for item in vulns:
                cve_obj = item.get("cve", {}) or {}
                cve_id = cve_obj.get("id")
                if not cve_id:
                    continue
                metrics = extract_metrics(item)
                record = {
                    "cve": cve_id,
                    "published": cve_obj.get("published"),
                    "lastModified": cve_obj.get("lastModified"),
                    "sourceIdentifier": cve_obj.get("sourceIdentifier"),
                    "kev": is_kev(item),
                    "metrics": metrics,
                    "severity": metrics.get("baseSeverity") or "None",
                    "score": metrics.get("baseScore"),
                    "refs": extract_references(item),
                    "matched_cpe_query": cpe,
                    "description": extract_description(item),
                    "cwes": extract_cwes(item),
                    "vulnStatus": cve_obj.get("vulnStatus"),
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
