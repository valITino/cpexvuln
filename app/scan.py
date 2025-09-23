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
    no_rejected=True,
    kev_only=False,
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
            vulns = fetch_for_cpe(session, cpe, since, now, api_key=api_key, insecure=insecure, no_rejected=no_rejected)
            any_success = True
            per_cpe[cpe] = iso(now)
            for v in vulns:
                c = v.get("cve", {}) or {}
                cve_id = c.get("id")
                if not cve_id: continue
                m = extract_metrics(v)
                rec = {
                    "cve": cve_id,
                    "published": c.get("published"),
                    "lastModified": c.get("lastModified"),
                    "sourceIdentifier": c.get("sourceIdentifier"),
                    "kev": is_kev(v),
                    "metrics": m,
                    "severity": m.get("baseSeverity") or "None",
                    "score": m.get("baseScore"),
                    "refs": extract_references(v),
                    "matched_cpe_query": cpe,
                    "description": extract_description(v),
                    "cwes": extract_cwes(v),
                    "vulnStatus": c.get("vulnStatus"),
                }
                prev = all_vulns.get(cve_id)
                if not prev or (rec["lastModified"] or "") > (prev.get("lastModified") or ""):
                    all_vulns[cve_id] = rec
        except Exception as e:
            print(f"[WARN] request failed for {cpe}: {e}")

    out_list = sorted(all_vulns.values(), key=lambda x: (x["lastModified"] or x["published"] or ""))

    updated = {"version": 3, "per_cpe": per_cpe}
    # mark long rescan if window >= ~90d
    if any_success and (now - since).days >= 89:
        updated["last_long_rescan"] = iso(now)
    else:
        if last_long_rescan:
            updated["last_long_rescan"] = last_long_rescan

    if kev_only:
        out_list = [r for r in out_list if r.get("kev")]

    return out_list, updated
