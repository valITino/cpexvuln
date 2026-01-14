"""
Core scanning logic for vulnerability detection.

This module handles the scanning of CPEs against the Vulnerability-Lookup API,
with state management for tracking what's been scanned.
"""

import logging
from typing import List, Tuple, Optional, Dict

from .utils import now_utc, iso, parse_iso
from .vulnerabilitylookup import (
    fetch_for_cpe,
    fetch_epss as fetch_epss_from_api,
    extract_metrics,
    is_kev,
    extract_kev_data,
    extract_epss,
    extract_description,
    extract_cwes,
    extract_references,
)

logger = logging.getLogger(__name__)


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

    logger.info(f"Starting scan for {len(cpes)} CPE(s)")
    logger.debug(f"Time window: {since} to {now}")
    logger.debug(f"State key: {state_key}")

    all_vulns: Dict[str, dict] = {}
    any_success = False
    failed_cpes = []
    successful_cpes = []

    for idx, cpe in enumerate(cpes, 1):
        logger.info(f"[{idx}/{len(cpes)}] Scanning CPE: {cpe}")
        try:
            vulns = fetch_for_cpe(
                session,
                cpe,
                since,
                now,
                insecure,
            )
            any_success = True
            successful_cpes.append(cpe)
            per_cpe[cpe] = iso(now)

            if vulns:
                logger.info(f"  Found {len(vulns)} vulnerabilities for {cpe}")
            else:
                logger.debug(f"  No vulnerabilities found for {cpe}")

            for item in vulns:
                # Vulnerability-Lookup format: CVE ID at top level or in 'id' field
                cve_id = item.get("id") or item.get("cve", {}).get("id")
                if not cve_id:
                    logger.debug(f"  Skipping vulnerability without CVE ID: {item.keys()}")
                    continue

                metrics = extract_metrics(item)
                epss_data = extract_epss(item)
                kev_flag = is_kev(item)
                kev_metadata = extract_kev_data(item) if kev_flag else {}

                # Get dates - Vulnerability-Lookup uses different field names
                published = item.get("Published") or item.get("published")
                last_modified = item.get("last-modified") or item.get("lastModified") or item.get("Modified")

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

        except Exception as exc:
            failed_cpes.append(cpe)
            logger.error(f"  Failed to scan {cpe}: {exc}")
            logger.debug(f"  Exception details:", exc_info=True)

    # Log scan summary
    logger.info(f"Scan complete: {len(successful_cpes)} CPEs successful, {len(failed_cpes)} failed")
    if failed_cpes:
        logger.warning(f"Failed CPEs: {', '.join(failed_cpes)}")
    logger.info(f"Total unique vulnerabilities found: {len(all_vulns)}")

    # Enrich vulnerabilities missing EPSS data
    vulns_missing_epss = [cve_id for cve_id, v in all_vulns.items() if v.get("epss") is None]
    if vulns_missing_epss:
        logger.info(f"Fetching EPSS scores for {len(vulns_missing_epss)} vulnerabilities...")
        for cve_id in vulns_missing_epss:
            try:
                epss_result = fetch_epss_from_api(session, cve_id, insecure)
                if epss_result:
                    all_vulns[cve_id]["epss"] = epss_result.get("epss")
                    all_vulns[cve_id]["epss_percentile"] = epss_result.get("percentile")
            except Exception as e:
                logger.debug(f"Failed to fetch EPSS for {cve_id}: {e}")

        # Count how many we enriched
        enriched = sum(1 for cve_id in vulns_missing_epss if all_vulns[cve_id].get("epss") is not None)
        logger.info(f"Enriched {enriched}/{len(vulns_missing_epss)} vulnerabilities with EPSS scores")

    # Sort by date
    out_list = sorted(
        all_vulns.values(),
        key=lambda value: (value["lastModified"] or value["published"] or ""),
        reverse=True  # Most recent first
    )

    # Update state
    updated = {"version": 3, "per_cpe": per_cpe}
    if any_success and (now - since).days >= 89:
        updated["last_long_rescan"] = iso(now)
        logger.debug("Long rescan completed - updating last_long_rescan timestamp")
    elif last_long_rescan:
        updated["last_long_rescan"] = last_long_rescan

    # Filter for KEV-only if requested
    if kev_only:
        kev_count = len([r for r in out_list if r.get("kev")])
        logger.info(f"KEV-only filter: {kev_count} KEV vulnerabilities out of {len(out_list)} total")
        out_list = [record for record in out_list if record.get("kev")]

    # Log severity breakdown
    severity_counts = {}
    for record in out_list:
        sev = record.get("severity", "None")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts:
        severity_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
        logger.info(f"Severity breakdown: {severity_str}")

    return out_list, updated
