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
DEFAULT_TIMEOUT = 60
DAILY_LOOKBACK_HOURS = 24      # daily window
LONG_BACKFILL_DAYS = 90        # backfill depth
BACKFILL_PERIOD_DAYS = 90      # do a 90d backfill every 90 days

# Scan scheduling configuration (times in 24h format: HH:MM)
SCAN_SCHEDULE = os.getenv("SCAN_SCHEDULE", "07:30,12:30,16:00,19:30").split(",")

# Scan history settings
SCAN_HISTORY_FILE = DATA_DIR / "scan_history.json"
SCAN_HISTORY_RETENTION_DAYS = int(os.getenv("SCAN_HISTORY_RETENTION_DAYS", "90"))

# Safety baseline for backlog reset (prevents scanning too far back in history)
BACKLOG_RESET_DATE = datetime(2025, 2, 26, 0, 0, 0, tzinfo=timezone.utc)
