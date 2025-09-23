"""Web UI for the CPE watch application."""
from __future__ import annotations

import csv
import io
import json
import os
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from .config import DAILY_LOOKBACK_HOURS, LONG_BACKFILL_DAYS, STATE_FILE, WATCHLISTS_FILE
from .nvd import build_session
from .scan import run_scan
from .utils import hash_for_cpes, load_json, now_utc, save_json


def create_app(args) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )
    app.secret_key = "dev-" + uuid.uuid4().hex

    def read_watchlists() -> dict:
        data = load_json(WATCHLISTS_FILE, {"lists": []})
        data["lists"] = list(data.get("lists", []))
        return data

    def write_watchlists(data: dict) -> None:
        save_json(WATCHLISTS_FILE, data)

    def render_with_watchlists(
        *,
        watchlists: List[dict],
        current: Optional[dict],
        results: Optional[List[dict]],
        window_label: str,
    ) -> str:
        return render_template(
            "index.html",
            watchlists=watchlists,
            current=current,
            results=results,
            window_label=window_label,
        )

    def build_session_for(current: dict) -> Tuple[Any, Dict[str, Any], Dict[str, str]]:
        session = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=current.get("insecure", False) or args.insecure,
            timeout=args.timeout,
        )
        state_all = load_json(STATE_FILE, {})
        state_key = f"nvd:{hash_for_cpes(current['cpes'])}"
        return session, state_all, {"state_key": state_key}

    def run_watch(current: dict, since) -> Tuple[List[dict], dict]:
        session, state_all, meta = build_session_for(current)
        results, updated_entry = run_scan(
            cpes=current["cpes"],
            state_all=state_all,
            state_key=meta["state_key"],
            session=session,
            insecure=current.get("insecure", False) or args.insecure,
            api_key=args.nvd_api_key,
            since=since,
            no_rejected=True,
            kev_only=False,
        )
        if updated_entry.get("per_cpe"):
            state_all[meta["state_key"]] = updated_entry
            save_json(STATE_FILE, state_all)
        return results, updated_entry

    @app.get("/favicon.ico")
    def favicon() -> Tuple[str, int]:
        return "", 204

    @app.get("/")
    def index():
        wl = read_watchlists()
        return render_with_watchlists(
            watchlists=wl["lists"], current=None, results=None, window_label=""
        )

    @app.get("/open/<wid>")
    def open_watchlist(wid: str):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        return render_with_watchlists(
            watchlists=wl["lists"], current=current, results=None, window_label=""
        )

    @app.post("/delete")
    def delete_lists():
        ids = [x for x in (request.form.get("ids") or "").split(",") if x]
        wl = read_watchlists()
        before = len(wl["lists"])
        wl["lists"] = [x for x in wl["lists"] if x["id"] not in ids]
        write_watchlists(wl)
        flash(f"Deleted {before - len(wl['lists'])} watchlist(s).")
        return redirect(url_for("index"))

    @app.get("/delete/<wid>")
    def delete_single(wid: str):
        wl = read_watchlists()
        wl["lists"] = [x for x in wl["lists"] if x["id"] != wid]
        write_watchlists(wl)
        flash("Deleted.")
        return redirect(url_for("index"))

    @app.get("/run/<wid>")
    def run_watchlist_view(wid: str):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        win = (request.args.get("win") or "24h").lower()
        since = now_utc() - (
            timedelta(hours=DAILY_LOOKBACK_HOURS)
            if win == "24h"
            else timedelta(days=LONG_BACKFILL_DAYS)
        )
        results, _ = run_watch(current, since)
        return render_with_watchlists(
            watchlists=wl["lists"],
            current=current,
            results=results,
            window_label=("last 24 hours" if win == "24h" else "last 90 days"),
        )

    @app.post("/submit")
    def submit():
        name = (request.form.get("name") or "").strip()
        cpes_raw = (request.form.get("cpes") or "").strip()
        action = request.form.get("action")
        insecure_flag = bool(request.form.get("insecure"))

        if not cpes_raw:
            flash("Please provide at least one CPE (comma-separated).")
            return redirect(url_for("index"))

        cpes = [c.strip() for c in cpes_raw.split(",") if c.strip()]
        if not cpes:
            flash("Could not parse any CPEs.")
            return redirect(url_for("index"))

        wl = read_watchlists()
        wid = str(uuid.uuid4())
        entry = {
            "id": wid,
            "name": name or f"List {len(wl['lists']) + 1}",
            "cpes": cpes,
            "insecure": insecure_flag,
        }
        wl["lists"].insert(0, entry)
        write_watchlists(wl)

        if action == "save_only":
            flash("Saved.")
            return redirect(url_for("open_watchlist", wid=wid))
        win = "24h" if action == "run_daily" else "90d"
        return redirect(url_for("run_watchlist_view", wid=wid, win=win))

    def _scan_for_export(wid: str, win: str) -> Tuple[Optional[dict], Optional[List[dict]]]:
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            return None, None
        since = now_utc() - (
            timedelta(hours=DAILY_LOOKBACK_HOURS)
            if win == "24h"
            else timedelta(days=LONG_BACKFILL_DAYS)
        )
        results, _ = run_watch(current, since)
        return current, results

    @app.get("/export/<wid>.json")
    def export_json(wid: str):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current or results is None:
            return Response("Not found", status=404)
        body = json.dumps(results, ensure_ascii=False, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{current["name"]}_{win}.json"'
            },
        )

    @app.get("/export/<wid>.csv")
    def export_csv(wid: str):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current or results is None:
            return Response("Not found", status=404)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "CVE",
            "Severity",
            "Score",
            "Published",
            "LastModified",
            "MatchedCPE",
            "KEV",
            "CWEs",
            "Description",
        ])
        for r in results:
            writer.writerow(
                [
                    r.get("cve", ""),
                    r.get("severity", ""),
                    r.get("score", ""),
                    r.get("published", ""),
                    r.get("lastModified", ""),
                    r.get("matched_cpe_query", ""),
                    "yes" if r.get("kev") else "",
                    ";".join(r.get("cwes", [])),
                    (r.get("description", "") or "").replace("\n", " ").strip(),
                ]
            )
        body = buf.getvalue()
        return Response(
            body,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{current["name"]}_{win}.csv"'
            },
        )

    return app

