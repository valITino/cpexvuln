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

# NVD / scan constants
API_BASE = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
MAX_RANGE_DAYS = 120
DEFAULT_TIMEOUT = 60
DAILY_LOOKBACK_HOURS = 24      # daily window
LONG_BACKFILL_DAYS = 90        # backfill depth
BACKFILL_PERIOD_DAYS = 90      # do a 90d backfill every 90 days

# Safety baseline for NVD's backlog reset
NVD_BACKLOG_RESET = datetime(2025, 2, 26, 0, 0, 0, tzinfo=timezone.utc)
