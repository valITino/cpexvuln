import os
from pathlib import Path
from datetime import datetime, timezone

# Root & data locations (all inside the project)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
OUT_DIR = DATA_DIR / "out"
STATE_FILE = DATA_DIR / "state.json"
WATCHLISTS_FILE = DATA_DIR / "watchlists.json"

# Create folders on import (cheap & safe)
OUT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Vulnerability-Lookup API constants
VULNERABILITY_LOOKUP_BASE = os.getenv("VULN_LOOKUP_API_BASE", "https://vulnerability.circl.lu/api")
DEFAULT_VULN_SOURCES = ["cvelist5", "nvd"]
DEFAULT_TIMEOUT = 60

# NVD API for CVSS fallback when scores are missing from primary source
NVD_API_BASE = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Optional: higher rate limits with API key
DAILY_LOOKBACK_HOURS = 24      # daily window
LONG_BACKFILL_DAYS = 90        # backfill depth
BACKFILL_PERIOD_DAYS = 90      # do a 90d backfill every 90 days

# Scan scheduling configuration (times in 24h format: HH:MM)
SCAN_SCHEDULE = os.getenv("SCAN_SCHEDULE", "07:30,12:30,16:00,19:30").split(",")

# Scan history settings
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"
SCAN_HISTORY_RETENTION_DAYS = int(os.getenv("SCAN_HISTORY_RETENTION_DAYS", "90"))

# Safety baseline for backlog reset
BACKLOG_RESET_DATE = datetime(2025, 2, 26, 0, 0, 0, tzinfo=timezone.utc)
