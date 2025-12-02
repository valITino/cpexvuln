from datetime import datetime, timedelta
from typing import Tuple, Dict

from .config import BACKLOG_RESET_DATE, DAILY_LOOKBACK_HOURS, LONG_BACKFILL_DAYS, BACKFILL_PERIOD_DAYS
from .utils import now_utc, parse_iso


def plan_window(state_entry: Dict, mode_auto: bool) -> Tuple[datetime, bool]:
    """
    (since_dt, is_long_backfill)
    - first run: 90-day backfill
    - every 90 days: 90-day backfill
    - otherwise: last 24h
    """
    now = now_utc()
    last_long = state_entry.get("last_long_rescan")
    if not last_long:
        return (max(now - timedelta(days=LONG_BACKFILL_DAYS), BACKLOG_RESET_DATE), True)
    last_long_dt = parse_iso(last_long)
    if mode_auto and (now - last_long_dt) >= timedelta(days=BACKFILL_PERIOD_DAYS):
        return (max(now - timedelta(days=LONG_BACKFILL_DAYS), BACKLOG_RESET_DATE), True)
    return (max(now - timedelta(hours=DAILY_LOOKBACK_HOURS), BACKLOG_RESET_DATE), False)
