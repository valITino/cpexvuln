from typing import List, Tuple, Dict

from .utils import now_utc, iso
from .config import DEFAULT_VULN_SOURCES
from .vulnerabilitylookup import (
    fetch_for_cpe,
    fetch_cisa_kev_data,
    fetch_epss,
    fetch_epss_first,
    fetch_nvd_cvss,
    extract_cve_id,
    extract_metrics,
    is_kev,
    extract_kev_data,
    extract_epss,
    extract_description,
    extract_cwes,
    extract_references,
    extract_source_identifier,
    extract_published_date,
    extract_last_modified_date,
)


def _record_timestamp(record: dict) -> str:
    return record.get("lastModified") or record.get("published") or ""


def _merge_records(primary: dict, secondary: dict) -> dict:
    merged = dict(primary)

    for key in ("published", "lastModified", "sourceIdentifier", "description", "matched_cpe_query", "vulnStatus"):
        if not merged.get(key) and secondary.get(key):
            merged[key] = secondary.get(key)

    if secondary.get("kev"):
        merged["kev"] = True
        kev_data = merged.get("kev_data") or {}
        kev_data.update(secondary.get("kev_data") or {})
        merged["kev_data"] = kev_data

    primary_score = merged.get("score")
    if primary_score is None and isinstance(merged.get("metrics"), dict):
        primary_score = merged["metrics"].get("baseScore")
    secondary_score = secondary.get("score")
    if secondary_score is None and isinstance(secondary.get("metrics"), dict):
        secondary_score = secondary["metrics"].get("baseScore")
    if primary_score is None and secondary_score is not None:
        merged["metrics"] = secondary.get("metrics")
        merged["score"] = secondary_score
        merged["severity"] = secondary.get("severity") or (secondary.get("metrics") or {}).get("baseSeverity")
    elif not merged.get("severity") and secondary.get("severity"):
        merged["severity"] = secondary.get("severity")

    if merged.get("epss") is None and secondary.get("epss") is not None:
        merged["epss"] = secondary.get("epss")
    if merged.get("epss_percentile") is None and secondary.get("epss_percentile") is not None:
        merged["epss_percentile"] = secondary.get("epss_percentile")

    if secondary.get("cwes"):
        merged_cwes = merged.get("cwes") or []
        merged["cwes"] = list(dict.fromkeys(merged_cwes + secondary.get("cwes", [])))

    if secondary.get("refs"):
        merged_refs = merged.get("refs") or []
        seen_urls = {ref.get("url") for ref in merged_refs if isinstance(ref, dict)}
        for ref in secondary.get("refs", []):
            if not isinstance(ref, dict):
                continue
            if ref.get("url") in seen_urls:
                continue
            merged_refs.append(ref)
            seen_urls.add(ref.get("url"))
        merged["refs"] = merged_refs

    return merged


def run_scan(
    cpes: List[str],
    state_all: dict,
    state_key: str,
    session,
    insecure: bool,
    since,
    kev_only: bool = False,
    sources: List[str] | None = None,
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
    normalized_sources = [s for s in (sources or DEFAULT_VULN_SOURCES) if s]
    entry = state_all.get(state_key) or {}
    per_cpe = dict(entry.get("per_cpe") or {})
    last_long_rescan = entry.get("last_long_rescan")

    all_vulns: Dict[str, dict] = {}
    any_success = False
    kev_map: Dict[str, Dict[str, object]] = {}

    try:
        kev_map = fetch_cisa_kev_data(session, insecure)
    except Exception:
        kev_map = {}

    for cpe in cpes:
        try:
            vulns = fetch_for_cpe(
                session,
                cpe,
                since,
                now,
                insecure,
                sources=normalized_sources,
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
                kev_from_record = is_kev(item)
                kev_from_catalog = cve_id.upper() in kev_map
                kev_flag = kev_from_record or kev_from_catalog
                kev_metadata = extract_kev_data(item) if kev_from_record else {}
                if kev_from_catalog:
                    kev_metadata = {**kev_map[cve_id.upper()], **kev_metadata}

                # Get dates - Vulnerability-Lookup uses different field names
                published = extract_published_date(item)
                last_modified = extract_last_modified_date(item)

                if metrics.get("baseScore") is None:
                    fetched_cvss = fetch_nvd_cvss(session, cve_id, insecure)
                    if fetched_cvss.get("baseScore") is not None:
                        metrics = fetched_cvss

                if epss_data.get("score") is None or epss_data.get("percentile") is None:
                    fetched_epss = fetch_epss(session, cve_id, insecure)
                    if epss_data.get("score") is None:
                        epss_data["score"] = fetched_epss.get("score")
                    if epss_data.get("percentile") is None:
                        epss_data["percentile"] = fetched_epss.get("percentile")

                if epss_data.get("score") is None or epss_data.get("percentile") is None:
                    fetched_epss = fetch_epss_first(session, cve_id, insecure)
                    if epss_data.get("score") is None:
                        epss_data["score"] = fetched_epss.get("score")
                    if epss_data.get("percentile") is None:
                        epss_data["percentile"] = fetched_epss.get("percentile")

                record = {
                    "cve": cve_id,
                    "published": published,
                    "lastModified": last_modified,
                    "sourceIdentifier": extract_source_identifier(item),
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
                if not previous:
                    all_vulns[cve_id] = record
                else:
                    if _record_timestamp(record) > _record_timestamp(previous):
                        all_vulns[cve_id] = _merge_records(record, previous)
                    else:
                        all_vulns[cve_id] = _merge_records(previous, record)
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
