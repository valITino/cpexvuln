"""
Entry point for Vulnerability Management System (Vulnerability-Lookup API).

Examples:
  # Start the web UI (localhost:5000)
  python main.py web --insecure

  # Run automated scheduler (scans at configured times)
  python main.py scheduler

  # Run a one-off scan (24h / 90d) from a CPE file
  python main.py run --cpes-file ./cpes/sample.txt --win 24h --insecure
"""

import os
import sys
import argparse
import json
import logging
from datetime import timedelta

# --- make sure we can import the package when running as a script ---
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    # Absolute imports from the package
    from app.web import create_app
    from app.scan import run_scan
    from app.vulnerabilitylookup import build_session
    from app.scheduler import get_scheduler
    from app.utils import load_json, save_json, now_utc, hash_for_cpes, ensure_dir, read_cpes_file
    from app.config import (
        STATE_FILE,
        OUT_DIR,
        DAILY_LOOKBACK_HOURS,
        LONG_BACKFILL_DAYS,
    )
except Exception as e:
    # Helpful message if the package can't be imported
    raise RuntimeError(
        "Failed to import the 'app' package. Make sure your project layout is:\n"
        f"{ROOT}\\\n"
        "  app\\__init__.py, web.py, scan.py, vulnerabilitylookup.py, utils.py, config.py\n"
        "  main.py\n\n"
        "If you prefer running as a module, use: python -m app.main web"
    ) from e


def add_common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--https-proxy", default=None, help="HTTPS proxy, e.g. https://user:pass@host:port")
    p.add_argument("--http-proxy", default=None, help="HTTP proxy, e.g. http://user:pass@host:port")
    p.add_argument("--ca-bundle", default=None, help="Path to custom CA bundle (PEM).")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (NOT recommended).")
    p.add_argument("--timeout", type=int, default=60, help="HTTP timeout (seconds).")


def main():
    ap = argparse.ArgumentParser(
        prog="main.py",
        description="Vulnerability Management System – web UI, scheduler, and scans",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # web subcommand
    webp = sub.add_parser("web", help="Start the web UI")
    add_common_flags(webp)
    webp.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    webp.add_argument("--port", type=int, default=5000, help="Bind port (default 5000)")
    webp.add_argument("--with-scheduler", action="store_true", help="Run scheduler alongside web UI")

    # scheduler subcommand
    schedp = sub.add_parser("scheduler", help="Run automated vulnerability scanning scheduler")
    schedp.add_argument("--once", action="store_true", help="Run all watchlists once and exit")

    # run subcommand
    runp = sub.add_parser("run", help="Run a one-off scan from a CPE file")
    add_common_flags(runp)
    runp.add_argument("--cpes-file", required=True, help="Text file with one CPE per line (or comma separated)")
    runp.add_argument(
        "--win",
        choices=["24h", "90d"],
        default="24h",
        help="Window to scan (24h or 90d)",
    )
    runp.add_argument("--out-dir", default=OUT_DIR, help="Directory to write NDJSON files")

    args = ap.parse_args()

    if args.cmd == "web":
        # Optionally start scheduler alongside web UI
        if args.with_scheduler:
            logger.info("Starting scheduler alongside web UI...")
            scheduler = get_scheduler()
            scheduler.start()

        # Pass flags into the Flask app factory so routes can reuse them
        app = create_app(args)
        # Disable reloader when running inside PyCharm debugger to avoid double-starts
        try:
            app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
        finally:
            if args.with_scheduler:
                scheduler.stop()
        return

    if args.cmd == "scheduler":
        logger.info("Starting vulnerability scanning scheduler...")
        scheduler = get_scheduler()

        if args.once:
            logger.info("Running all watchlists once...")
            scheduler.run_all_watchlists()
            logger.info("One-time scan complete.")
        else:
            logger.info("Starting continuous scheduler. Press Ctrl+C to stop.")
            scheduler.start()
            try:
                # Keep the main thread alive
                import time
                while scheduler.is_running():
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Stopping scheduler...")
                scheduler.stop()
        return

    if args.cmd == "run":
        # Read CPEs (allow comma-separated line as well)
        cpes = []
        if os.path.isfile(args.cpes_file):
            cpes = read_cpes_file(args.cpes_file)
        else:
            # Fall back: parse a comma-separated string
            cpes = [x.strip() for x in args.cpes_file.split(",") if x.strip()]

        if not cpes:
            print("No CPEs found to scan.")
            sys.exit(2)

        # HTTP session
        session = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=args.insecure,
            timeout=args.timeout,
        )

        # Pick window
        now = now_utc()
        if args.win == "24h":
            since = now - timedelta(hours=DAILY_LOOKBACK_HOURS)
        else:
            since = now - timedelta(days=LONG_BACKFILL_DAYS)

        # Stateful dedupe per unique CPE set
        state_all = load_json(STATE_FILE, {})
        state_key = f"vuln:{hash_for_cpes(cpes)}"

        results, updated_entry = run_scan(
            cpes=cpes,
            state_all=state_all,
            state_key=state_key,
            session=session,
            insecure=args.insecure,
            since=since,
            kev_only=False,
        )

        # Save state
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)

        # Write NDJSON
        ensure_dir(args.out_dir)
        ts = now.strftime("%Y-%m-%d_%H%MZ")
        out_path = os.path.join(args.out_dir, f"vuln_{ts}.jsonl")
        with open(out_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        print(f"[info] wrote {len(results)} CVEs -> {out_path}")
        return


if __name__ == "__main__":
    main()
