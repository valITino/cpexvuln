"""
Automated scanning scheduler for vulnerability monitoring.
Runs scans at configured times (default: 07:30, 12:30, 16:00, 19:30).
"""
import os
import threading
from datetime import datetime, timedelta
from typing import Optional
import logging

from .config import SCAN_SCHEDULE, WATCHLISTS_FILE, STATE_FILE, DAILY_LOOKBACK_HOURS
from .utils import load_json, now_utc
from .vulnerabilitylookup import build_session
from .scan import run_scan
from .scan_history import add_scan_result
from .utils import hash_for_cpes

logger = logging.getLogger(__name__)


class ScanScheduler:
    """
    Manages scheduled vulnerability scans for all watchlists.
    """

    def __init__(self, scan_times: Optional[list] = None, session_defaults: Optional[dict] = None):
        """
        Initialize the scheduler.

        Args:
            scan_times: List of scan times in HH:MM format (default: from config)
        """
        self.default_scan_times = scan_times or SCAN_SCHEDULE
        self.session_defaults = session_defaults or {}
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def update_defaults(self, scan_times: Optional[list] = None, session_defaults: Optional[dict] = None):
        """Update scheduler defaults for scan times or session settings."""
        if scan_times is not None:
            self.default_scan_times = scan_times
        if session_defaults:
            self.session_defaults.update(session_defaults)

    def parse_time(self, time_str: str) -> Optional[tuple]:
        """Parse HH:MM format into (hour, minute) tuple."""
        try:
            parts = time_str.strip().split(":")
            hour = int(parts[0])
            minute = int(parts[1]) if len(parts) > 1 else 0
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError("Out of range")
            return (hour, minute)
        except (ValueError, IndexError):
            logger.error(f"Invalid time format: {time_str}, expected HH:MM")
            return None

    def normalize_scan_times(self, raw_times) -> list:
        """Normalize scan times input into sorted list of unique HH:MM strings."""
        if raw_times is None:
            return []
        if isinstance(raw_times, str):
            times = [t.strip() for t in raw_times.split(",")]
        elif isinstance(raw_times, list):
            times = [str(t).strip() for t in raw_times]
        else:
            times = []
        return sorted({t for t in times if t})

    def _load_watchlists(self) -> list:
        wl_data = load_json(WATCHLISTS_FILE, default={"lists": []})
        return wl_data.get("lists", [])

    def _watchlist_scan_times(self, watchlist: dict) -> list:
        options = watchlist.get("options", {}) or {}
        schedule_times = options.get("scheduleTimes")
        times = self.normalize_scan_times(schedule_times)
        return times or self.normalize_scan_times(self.default_scan_times)

    def _scan_times_pool(self, watchlists: list) -> list:
        times: list = []
        for watch in watchlists:
            times.extend(self._watchlist_scan_times(watch))
        if not times:
            times = self.normalize_scan_times(self.default_scan_times)
        return times

    def get_next_scan_time(self) -> datetime:
        """
        Calculate the next scheduled scan time.

        Returns:
            datetime object for the next scan
        """
        now = now_utc()
        today = now.date()
        watchlists = self._load_watchlists()

        # Parse all scan times
        scan_times_parsed = []
        for time_str in self._scan_times_pool(watchlists):
            parsed = self.parse_time(time_str)
            if parsed:
                scan_times_parsed.append(parsed)

        # Create datetime objects for today's scan times
        scheduled_times = []
        for hour, minute in scan_times_parsed:
            scan_dt = datetime(
                today.year, today.month, today.day,
                hour, minute, 0,
                tzinfo=now.tzinfo
            )
            scheduled_times.append(scan_dt)

        # Find next scan time
        future_times = [t for t in scheduled_times if t > now]

        if future_times:
            return min(future_times)
        else:
            # All times are in the past, schedule for tomorrow's first scan
            if scheduled_times:
                earliest = min(scheduled_times)
                tomorrow = earliest + timedelta(days=1)
                return tomorrow
            else:
                # No scan times configured, default to 1 hour from now
                return now + timedelta(hours=1)

    def _should_run_watchlist(self, watchlist: dict, run_at: datetime) -> bool:
        for time_str in self._watchlist_scan_times(watchlist):
            parsed = self.parse_time(time_str)
            if not parsed:
                continue
            hour, minute = parsed
            if run_at.hour == hour and run_at.minute == minute:
                return True
        return False

    def _run_watchlists(self, watchlists: list):
        """
        Execute scans for all configured watchlists.
        """
        logger.info("Starting scheduled scan for watchlists...")

        try:
            if not watchlists:
                logger.info("No watchlists configured, skipping scan.")
                return

            # Load state
            state_all = load_json(STATE_FILE, default={})

            # Scan each watchlist
            for watchlist in watchlists:
                wl_id = watchlist.get("id")
                wl_name = watchlist.get("name", "Unnamed")
                cpes = watchlist.get("cpes", [])
                options = watchlist.get("options", {}) or {}
                insecure = options.get("insecure", False)
                sources = options.get("sources")

                if not cpes:
                    logger.warning(f"Watchlist '{wl_name}' has no CPEs, skipping.")
                    continue

                logger.info(f"Scanning watchlist: {wl_name} ({len(cpes)} CPEs)")

                try:
                    https_proxy = (
                        options.get("httpsProxy")
                        or self.session_defaults.get("https_proxy")
                        or os.environ.get("HTTPS_PROXY")
                    )
                    http_proxy = (
                        options.get("httpProxy")
                        or self.session_defaults.get("http_proxy")
                        or os.environ.get("HTTP_PROXY")
                    )
                    ca_bundle = options.get("caBundle") or self.session_defaults.get("ca_bundle")
                    timeout = int(options.get("timeout") or self.session_defaults.get("timeout") or 60)
                    session = build_session(
                        https_proxy=https_proxy,
                        http_proxy=http_proxy,
                        ca_bundle=ca_bundle,
                        insecure=insecure or self.session_defaults.get("insecure", False),
                        timeout=timeout,
                    )
                    # Use 24-hour lookback for scheduled scans
                    since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
                    state_key = f"vuln:{hash_for_cpes(cpes)}"

                    # Run scan
                    results, updated_state = run_scan(
                        cpes=cpes,
                        state_all=state_all,
                        state_key=state_key,
                        session=session,
                        insecure=insecure,
                        since=since,
                        kev_only=options.get("hasKev", False),
                        sources=sources,
                    )

                    # Update state
                    state_all[state_key] = updated_state

                    # Add to scan history
                    add_scan_result(
                        watchlist_id=wl_id,
                        watchlist_name=wl_name,
                        cpes=cpes,
                        cve_records=results,
                        scan_window="24h"
                    )

                    logger.info(f"Scan complete for '{wl_name}': {len(results)} vulnerabilities found")

                except Exception as exc:
                    logger.error(f"Scan failed for watchlist '{wl_name}': {exc}")

            # Save updated state
            from .utils import save_json
            save_json(STATE_FILE, state_all)

            logger.info("Scheduled scan complete.")

        except Exception as exc:
            logger.error(f"Error during scheduled scan: {exc}")

    def run_all_watchlists(self):
        watchlists = self._load_watchlists()
        logger.info("Starting scheduled scan for all watchlists...")
        self._run_watchlists(watchlists)

    def run_due_watchlists(self, run_at: Optional[datetime] = None):
        run_at = run_at or now_utc()
        watchlists = self._load_watchlists()
        due = [wl for wl in watchlists if self._should_run_watchlist(wl, run_at)]
        if not due:
            logger.info("No watchlists scheduled for this time.")
            return
        self._run_watchlists(due)

    def _scheduler_loop(self):
        """
        Main scheduler loop that runs in a background thread.
        """
        logger.info(f"Scheduler started with times: {self.default_scan_times}")

        while not self._stop_event.is_set():
            next_scan = self.get_next_scan_time()
            now = now_utc()
            wait_seconds = (next_scan - now).total_seconds()

            logger.info(f"Next scan scheduled for: {next_scan.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            logger.info(f"Waiting {wait_seconds/3600:.1f} hours until next scan...")

            # Wait in small intervals to allow for clean shutdown
            while wait_seconds > 0 and not self._stop_event.is_set():
                sleep_time = min(60, wait_seconds)  # Check every minute
                self._stop_event.wait(sleep_time)
                wait_seconds -= sleep_time

            # If we're stopping, exit the loop
            if self._stop_event.is_set():
                break

            # Run the scans
            try:
                self.run_due_watchlists(next_scan)
            except Exception as exc:
                logger.error(f"Scheduled scan failed: {exc}")

        logger.info("Scheduler stopped.")

    def start(self):
        """
        Start the scheduler in a background thread.
        """
        if self.running:
            logger.warning("Scheduler is already running.")
            return

        self.running = True
        self._stop_event.clear()
        self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()
        logger.info("Scheduler thread started.")

    def stop(self):
        """
        Stop the scheduler gracefully.
        """
        if not self.running:
            return

        logger.info("Stopping scheduler...")
        self.running = False
        self._stop_event.set()

        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None

        logger.info("Scheduler stopped.")

    def is_running(self) -> bool:
        """Check if scheduler is currently running."""
        return self.running and self.thread and self.thread.is_alive()


# Global scheduler instance
_scheduler_instance: Optional[ScanScheduler] = None


def get_scheduler(scan_times: Optional[list] = None, session_defaults: Optional[dict] = None) -> ScanScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = ScanScheduler(scan_times=scan_times, session_defaults=session_defaults)
    elif scan_times is not None or session_defaults:
        _scheduler_instance.update_defaults(scan_times=scan_times, session_defaults=session_defaults)
    return _scheduler_instance


def start_scheduler():
    """Start the global scheduler."""
    scheduler = get_scheduler()
    scheduler.start()


def stop_scheduler():
    """Stop the global scheduler."""
    scheduler = get_scheduler()
    scheduler.stop()
