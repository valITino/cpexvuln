from typing import Any, Dict, List, Optional, Tuple

from .utils import iso, now_utc
from .nvd import (
    extract_affected_cpes,
    extract_cwes,
    extract_description,
    extract_references,
    fetch_for_cpe,
    is_kev,
    pick_preferred_cvss,
)


def run_scan(
    cpes: List[str],
    state_all: dict,
    state_key: str,
    session,
    insecure: bool,
    api_key: Optional[str],
    since,
    *,
    no_rejected: bool = True,
    kev_only: bool = False,
    min_score: Optional[float] = None,
    is_vulnerable: bool = False,
    extra_params: Optional[Dict[str, Any]] = None,
) -> Tuple[List[dict], dict]:
    """Run a scan across all provided CPE strings."""

    now = now_utc()
    entry = state_all.get(state_key) or {}
    per_cpe = dict(entry.get("per_cpe") or {})
    last_long_rescan = entry.get("last_long_rescan")

    results: Dict[str, Dict[str, Any]] = {}
    any_success = False
    extra_params = extra_params or {}

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
                is_vulnerable=is_vulnerable,
                extra_params=extra_params,
            )
        except Exception as exc:  # pragma: no cover - network edge cases
            print(f"[WARN] request failed for {cpe}: {exc}")
            continue

        any_success = True
        per_cpe[cpe] = iso(now)

        for vuln in vulns:
            cve_obj = vuln.get("cve", {}) or {}
            cve_id = cve_obj.get("id")
            if not cve_id:
                continue

            record = results.get(cve_id)
            metrics = pick_preferred_cvss(cve_obj.get("metrics") or {})
            affected = extract_affected_cpes(vuln)

            if not record:
                record = {
                    "id": cve_id,
                    "published": cve_obj.get("published"),
                    "lastModified": cve_obj.get("lastModified"),
                    "sourceIdentifier": cve_obj.get("sourceIdentifier"),
                    "kev": is_kev(vuln),
                    "description": extract_description(vuln),
                    "cwes": extract_cwes(vuln),
                    "references": extract_references(vuln),
                    "affectedCPE": set(affected),
                    "matchedCPE": {cpe},
                    "cvss": metrics,
                    "cvssScore": metrics.get("baseScore"),
                    "cvssSeverity": metrics.get("baseSeverity"),
                    "cvssVector": metrics.get("vectorString"),
                    "vulnStatus": cve_obj.get("vulnStatus"),
                }
                results[cve_id] = record
            else:
                record["kev"] = record["kev"] or is_kev(vuln)
                record["affectedCPE"].update(affected)
                record["matchedCPE"].add(cpe)
                last_mod = cve_obj.get("lastModified")
                if last_mod and (record.get("lastModified") or "") < last_mod:
                    record["lastModified"] = last_mod
                    record["published"] = cve_obj.get("published") or record["published"]
                    record["sourceIdentifier"] = cve_obj.get("sourceIdentifier") or record.get("sourceIdentifier")
                new_metrics = pick_preferred_cvss(cve_obj.get("metrics") or {})
                if (new_metrics.get("baseScore") or -1) >= (record["cvss"].get("baseScore") or -1):
                    record["cvss"] = new_metrics
                    record["cvssScore"] = new_metrics.get("baseScore")
                    record["cvssSeverity"] = new_metrics.get("baseSeverity")
                    record["cvssVector"] = new_metrics.get("vectorString")

    updated = {"version": 4, "per_cpe": per_cpe}
    if any_success and (now - since).days >= 89:
        updated["last_long_rescan"] = iso(now)
    elif last_long_rescan:
        updated["last_long_rescan"] = last_long_rescan

    min_score_val: Optional[float]
    try:
        min_score_val = float(min_score) if min_score is not None else None
    except (TypeError, ValueError):
        min_score_val = None

    out: List[Dict[str, Any]] = []
    for record in results.values():
        record["affectedCPE"] = sorted(record["affectedCPE"].union(record["matchedCPE"]))
        record["matchedCPE"] = sorted(record["matchedCPE"])

        score = record.get("cvssScore")
        if kev_only and not record.get("kev"):
            continue
        if min_score_val is not None:
            try:
                score_val = float(score)
            except (TypeError, ValueError):
                continue
            if score_val < min_score_val:
                continue

        out.append(record)

    out.sort(key=lambda x: (x.get("lastModified") or x.get("published") or ""), reverse=True)
    return out, updated
