"""
Automated scanning scheduler for vulnerability monitoring.
Runs scans at configured times (default: 07:30, 12:30, 16:00, 19:30).
"""
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Optional
import logging

import os
from .config import SCAN_SCHEDULE, WATCHLISTS_FILE, STATE_FILE, DAILY_LOOKBACK_HOURS, get_ca_bundle_from_env
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

    def __init__(self, scan_times: Optional[list] = None):
        """
        Initialize the scheduler.

        Args:
            scan_times: List of scan times in HH:MM format (default: from config)
        """
        self.scan_times = scan_times or SCAN_SCHEDULE
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def parse_time(self, time_str: str) -> tuple:
        """Parse HH:MM format into (hour, minute) tuple."""
        try:
            parts = time_str.strip().split(":")
            hour = int(parts[0])
            minute = int(parts[1]) if len(parts) > 1 else 0
            return (hour, minute)
        except (ValueError, IndexError):
            logger.error(f"Invalid time format: {time_str}, expected HH:MM")
            return (0, 0)

    def get_next_scan_time(self) -> datetime:
        """
        Calculate the next scheduled scan time.

        Returns:
            datetime object for the next scan
        """
        now = now_utc()
        today = now.date()

        # Parse all scan times
        scan_times_parsed = [self.parse_time(t) for t in self.scan_times]

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

    def run_all_watchlists(self):
        """
        Execute scans for all configured watchlists.
        """
        logger.info("Starting scheduled scan for all watchlists...")

        try:
            # Load watchlists
            wl_data = load_json(WATCHLISTS_FILE, default={"lists": []})
            watchlists = wl_data.get("lists", [])

            if not watchlists:
                logger.info("No watchlists configured, skipping scan.")
                return

            # Load state
            state_all = load_json(STATE_FILE, default={})

            # Build session with proxy and certificate support from environment
            ca_bundle = get_ca_bundle_from_env()
            https_proxy = os.environ.get("HTTPS_PROXY")
            http_proxy = os.environ.get("HTTP_PROXY")

            if ca_bundle:
                logger.info(f"Using CA bundle from environment: {ca_bundle}")
            if https_proxy:
                logger.debug(f"Using HTTPS proxy from environment")
            if http_proxy:
                logger.debug(f"Using HTTP proxy from environment")

            session = build_session(
                https_proxy=https_proxy,
                http_proxy=http_proxy,
                ca_bundle=ca_bundle,
            )

            # Scan each watchlist
            for watchlist in watchlists:
                wl_id = watchlist.get("id")
                wl_name = watchlist.get("name", "Unnamed")
                cpes = watchlist.get("cpes", [])
                insecure = watchlist.get("insecure", False)

                if not cpes:
                    logger.warning(f"Watchlist '{wl_name}' has no CPEs, skipping.")
                    continue

                logger.info(f"Scanning watchlist: {wl_name} ({len(cpes)} CPEs)")

                try:
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
                        kev_only=False,
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

            logger.info("Scheduled scan complete for all watchlists.")

        except Exception as exc:
            logger.error(f"Error during scheduled scan: {exc}")

    def _scheduler_loop(self):
        """
        Main scheduler loop that runs in a background thread.
        """
        logger.info(f"Scheduler started with times: {self.scan_times}")

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
                self.run_all_watchlists()
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


def get_scheduler() -> ScanScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = ScanScheduler()
    return _scheduler_instance


def start_scheduler():
    """Start the global scheduler."""
    scheduler = get_scheduler()
    scheduler.start()


def stop_scheduler():
    """Stop the global scheduler."""
    scheduler = get_scheduler()
    scheduler.stop()
