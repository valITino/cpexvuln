"""
Scan history management for tracking vulnerability changes over time.
Enables "New" vulnerability detection by comparing consecutive scans.
"""
from typing import List, Dict, Any, Optional
from datetime import timedelta
import uuid

from .utils import now_utc, iso, parse_iso, load_json, save_json
from .config import SCAN_HISTORY_FILE, SCAN_HISTORY_RETENTION_DAYS


def get_scan_history() -> Dict[str, Any]:
    """Load scan history from file."""
    data = load_json(SCAN_HISTORY_FILE, default={"scans": []})
    if "scans" not in data:
        data["scans"] = []
    return data


def save_scan_history(data: Dict[str, Any]) -> None:
    """Save scan history to file."""
    save_json(SCAN_HISTORY_FILE, data)


def cleanup_old_scans(history: Dict[str, Any], retention_days: int = SCAN_HISTORY_RETENTION_DAYS) -> Dict[str, Any]:
    """Remove scans older than retention period."""
    cutoff = now_utc() - timedelta(days=retention_days)
    scans = history.get("scans", [])

    filtered_scans = []
    for scan in scans:
        scan_time = parse_iso(scan.get("timestamp", ""))
        if scan_time >= cutoff:
            filtered_scans.append(scan)

    history["scans"] = filtered_scans
    return history


def add_scan_result(
    watchlist_id: str,
    watchlist_name: str,
    cpes: List[str],
    cve_records: List[Dict[str, Any]],
    scan_window: str = "24h"
) -> str:
    """
    Add a new scan result to history.

    Returns the scan ID.
    """
    history = get_scan_history()

    # Cleanup old scans before adding new one
    history = cleanup_old_scans(history)

    # Calculate summary statistics
    summary = calculate_summary(cve_records)

    # Create scan record
    scan_id = str(uuid.uuid4())
    scan_record = {
        "id": scan_id,
        "timestamp": iso(now_utc()),
        "watchlist_id": watchlist_id,
        "watchlist_name": watchlist_name,
        "cpes": cpes,
        "window": scan_window,
        "cve_ids": [record["cve"] for record in cve_records],
        "summary": summary,
        "total_count": len(cve_records),
    }

    history["scans"].append(scan_record)
    save_scan_history(history)

    return scan_id


def calculate_summary(cve_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate summary statistics for a scan."""
    total = len(cve_records)
    critical = sum(1 for r in cve_records if r.get("severity") == "Critical")
    high = sum(1 for r in cve_records if r.get("severity") == "High")
    medium = sum(1 for r in cve_records if r.get("severity") == "Medium")
    low = sum(1 for r in cve_records if r.get("severity") == "Low")
    kev_count = sum(1 for r in cve_records if r.get("kev"))

    # EPSS statistics (for CVEs with EPSS scores)
    epss_scores = [r.get("epss") for r in cve_records if r.get("epss") is not None]
    epss_high_count = sum(1 for score in epss_scores if score >= 0.5)

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "kev_count": kev_count,
        "epss_high_count": epss_high_count,  # EPSS >= 0.5 (50% exploitation probability)
    }


def get_previous_scan(watchlist_id: str, before_timestamp: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Get the most recent scan for a watchlist before a given timestamp.

    Args:
        watchlist_id: The watchlist ID to search for
        before_timestamp: ISO timestamp to search before (default: now)

    Returns:
        Previous scan record or None if not found
    """
    history = get_scan_history()
    scans = history.get("scans", [])

    # Filter scans for this watchlist
    watchlist_scans = [s for s in scans if s.get("watchlist_id") == watchlist_id]

    if not watchlist_scans:
        return None

    # Sort by timestamp descending
    watchlist_scans.sort(key=lambda s: s.get("timestamp", ""), reverse=True)

    # If no before_timestamp, return the most recent
    if not before_timestamp:
        return watchlist_scans[0] if watchlist_scans else None

    # Find most recent scan before the given timestamp
    before_dt = parse_iso(before_timestamp)
    for scan in watchlist_scans:
        scan_dt = parse_iso(scan.get("timestamp", ""))
        if scan_dt < before_dt:
            return scan

    return None


def compare_scans(current_cves: List[str], previous_cves: List[str]) -> Dict[str, Any]:
    """
    Compare two sets of CVE IDs and return the differences.

    Returns:
        {
            "new": [...],      # CVEs in current but not in previous
            "removed": [...],  # CVEs in previous but not in current
            "common": [...]    # CVEs in both
        }
    """
    current_set = set(current_cves)
    previous_set = set(previous_cves)

    return {
        "new": sorted(list(current_set - previous_set)),
        "removed": sorted(list(previous_set - current_set)),
        "common": sorted(list(current_set & previous_set)),
    }


def get_new_vulnerabilities(
    cve_records: List[Dict[str, Any]],
    watchlist_id: str,
    compare_to_scan: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Filter CVE records to only those that are new compared to a previous scan.

    Args:
        cve_records: Current scan results
        watchlist_id: Watchlist ID
        compare_to_scan: Timestamp of scan to compare to (default: most recent previous scan)

    Returns:
        List of CVE records that are new
    """
    previous_scan = get_previous_scan(watchlist_id, before_timestamp=compare_to_scan)

    if not previous_scan:
        # No previous scan - all CVEs are "new"
        return cve_records

    previous_cve_ids = set(previous_scan.get("cve_ids", []))
    current_cve_ids = [r["cve"] for r in cve_records]

    # Find new CVE IDs
    new_cve_ids = set(current_cve_ids) - previous_cve_ids

    # Filter records
    return [r for r in cve_records if r["cve"] in new_cve_ids]


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific scan by ID."""
    history = get_scan_history()
    scans = history.get("scans", [])

    for scan in scans:
        if scan.get("id") == scan_id:
            return scan

    return None


def get_scans_for_watchlist(watchlist_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get recent scans for a watchlist.

    Args:
        watchlist_id: The watchlist ID
        limit: Maximum number of scans to return

    Returns:
        List of scan records, most recent first
    """
    history = get_scan_history()
    scans = history.get("scans", [])

    # Filter and sort
    watchlist_scans = [s for s in scans if s.get("watchlist_id") == watchlist_id]
    watchlist_scans.sort(key=lambda s: s.get("timestamp", ""), reverse=True)

    return watchlist_scans[:limit]


def get_time_based_filter(cve_records: List[Dict[str, Any]], hours: int) -> List[Dict[str, Any]]:
    """
    Filter CVE records by age (based on published date).

    Args:
        cve_records: List of CVE records
        hours: Maximum age in hours

    Returns:
        Filtered list of CVEs published within the time window
    """
    cutoff = now_utc() - timedelta(hours=hours)

    filtered = []
    for record in cve_records:
        published = record.get("published")
        if published:
            pub_date = parse_iso(published)
            if pub_date >= cutoff:
                filtered.append(record)
        else:
            # Include if no published date
            filtered.append(record)

    return filtered
