import os
import uuid
import csv
import io
import json
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify, session

from .config import WATCHLISTS_FILE, STATE_FILE, DAILY_LOOKBACK_HOURS, LONG_BACKFILL_DAYS, DEFAULT_VULN_SOURCES
from .utils import load_json, save_json, now_utc, hash_for_cpes
from .vulnerabilitylookup import build_session
from .scan import run_scan
from .scan_history import add_scan_result, get_new_vulnerabilities


def create_app(args):
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-" + secrets.token_hex(16))

    def read_watchlists():
        wl = load_json(WATCHLISTS_FILE, {"lists": [], "projects": []})
        wl["lists"] = wl.get("lists", [])
        wl["projects"] = wl.get("projects", [])
        return wl

    def write_watchlists(data):
        save_json(WATCHLISTS_FILE, data)

    def generate_csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)
        return session["_csrf_token"]

    def normalize_sources(raw_sources):
        if not raw_sources:
            return list(DEFAULT_VULN_SOURCES)
        if isinstance(raw_sources, str):
            sources = [s.strip() for s in raw_sources.split(",") if s.strip()]
        elif isinstance(raw_sources, list):
            sources = [str(s).strip() for s in raw_sources if str(s).strip()]
        else:
            sources = []

        allowed = {source.lower(): source for source in DEFAULT_VULN_SOURCES}
        filtered = [allowed[s.lower()] for s in sources if s.lower() in allowed]
        return filtered or list(DEFAULT_VULN_SOURCES)

    def normalize_schedule_times(raw_times):
        if raw_times is None:
            return []
        if isinstance(raw_times, str):
            times = [t.strip() for t in raw_times.split(",")]
        elif isinstance(raw_times, list):
            times = [str(t).strip() for t in raw_times]
        else:
            times = []
        return sorted({t for t in times if t})

    def csrf_token():
        return generate_csrf_token()

    @app.context_processor
    def inject_csrf():
        return dict(csrf_token=csrf_token)

    def check_csrf():
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not token or token != session.get("_csrf_token"):
            return False
        return True

    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    # ========================================
    # SPA Frontend (New Design)
    # ========================================

    @app.get("/")
    def index():
        wl = read_watchlists()
        # Build bootstrap data for the SPA
        bootstrap = {
            "csrfToken": generate_csrf_token(),
            "projects": wl.get("projects", []),
            "lists": wl.get("lists", []),
            "currentWatchId": None,
            "results": [],
            "windowLabel": "",
            "issues": [],
        }
        return render_template("index.html", bootstrap=bootstrap)

    # ========================================
    # SPA API Endpoints
    # ========================================

    @app.get("/api/watchlists")
    def api_get_watchlists():
        wl = read_watchlists()
        return jsonify({
            "projects": wl.get("projects", []),
            "lists": wl.get("lists", []),
        })

    @app.post("/api/projects")
    def api_create_project():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        data = request.get_json() or {}
        name = data.get("name", "").strip() or "New Team"
        wl = read_watchlists()
        project_id = str(uuid.uuid4())
        project = {
            "id": project_id,
            "name": name,
            "order": len(wl.get("projects", [])),
        }
        wl.setdefault("projects", []).append(project)
        write_watchlists(wl)
        return jsonify({"project": project})

    @app.route("/api/projects/<project_id>", methods=["PATCH", "DELETE"])
    def api_project(project_id):
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        wl = read_watchlists()

        if request.method == "DELETE":
            # Check if project has watchlists
            has_lists = any(w.get("projectId") == project_id for w in wl.get("lists", []))
            if has_lists:
                return jsonify({"error": "Cannot delete team with watchlists. Delete watchlists first."}), 400
            wl["projects"] = [p for p in wl.get("projects", []) if p["id"] != project_id]
            write_watchlists(wl)
            return jsonify({"ok": True})

        # PATCH - rename
        data = request.get_json() or {}
        for project in wl.get("projects", []):
            if project["id"] == project_id:
                project["name"] = data.get("name", project["name"])
                break
        write_watchlists(wl)
        return jsonify({"ok": True})

    @app.post("/api/watchlists")
    def api_create_watchlist():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        data = request.get_json() or {}
        wl = read_watchlists()

        # Parse CPEs
        cpes_raw = data.get("cpes", "")
        if isinstance(cpes_raw, list):
            cpes = [c.strip() for c in cpes_raw if c.strip()]
        else:
            cpes = [c.strip() for c in cpes_raw.split(",") if c.strip()]

        # Ensure project exists
        project_id = data.get("projectId")
        if not project_id:
            # Create default project if none specified
            if not wl.get("projects"):
                project_id = str(uuid.uuid4())
                wl["projects"] = [{"id": project_id, "name": "Default Team", "order": 0}]
            else:
                project_id = wl["projects"][0]["id"]

        options = data.get("options", {}) or {}
        options["sources"] = normalize_sources(options.get("sources"))
        options["scheduleTimes"] = normalize_schedule_times(options.get("scheduleTimes"))
        watchlist = {
            "id": str(uuid.uuid4()),
            "name": data.get("name", "").strip() or f"Watchlist {len(wl.get('lists', [])) + 1}",
            "projectId": project_id,
            "cpes": cpes,
            "comments": data.get("comments", ""),
            "options": options,
            "order": len([w for w in wl.get("lists", []) if w.get("projectId") == project_id]),
        }
        wl.setdefault("lists", []).append(watchlist)
        write_watchlists(wl)
        return jsonify({"watchlist": watchlist})

    @app.route("/api/watchlists/<watchlist_id>", methods=["PUT", "DELETE"])
    def api_watchlist(watchlist_id):
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        wl = read_watchlists()

        if request.method == "DELETE":
            wl["lists"] = [w for w in wl.get("lists", []) if w["id"] != watchlist_id]
            write_watchlists(wl)
            return jsonify({"ok": True})

        # PUT - update
        data = request.get_json() or {}
        for watchlist in wl.get("lists", []):
            if watchlist["id"] == watchlist_id:
                # Parse CPEs
                cpes_raw = data.get("cpes", "")
                if isinstance(cpes_raw, list):
                    cpes = [c.strip() for c in cpes_raw if c.strip()]
                else:
                    cpes = [c.strip() for c in cpes_raw.split(",") if c.strip()]

                watchlist["name"] = data.get("name", watchlist.get("name", ""))
                watchlist["cpes"] = cpes if cpes else watchlist.get("cpes", [])
                watchlist["comments"] = data.get("comments", watchlist.get("comments", ""))
                options = data.get("options", watchlist.get("options", {})) or {}
                options["sources"] = normalize_sources(options.get("sources"))
                schedule_times = options.get("scheduleTimes", watchlist.get("options", {}).get("scheduleTimes"))
                options["scheduleTimes"] = normalize_schedule_times(schedule_times)
                watchlist["options"] = options
                if data.get("projectId"):
                    watchlist["projectId"] = data["projectId"]
                write_watchlists(wl)
                return jsonify({"watchlist": watchlist})

        return jsonify({"error": "Watchlist not found"}), 404

    @app.post("/api/run")
    def api_run():
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        data = request.get_json() or {}
        watchlist_id = data.get("watchlistId")
        win = (data.get("window") or "24h").lower()

        wl = read_watchlists()
        current = next((w for w in wl.get("lists", []) if w["id"] == watchlist_id), None)
        if not current:
            return jsonify({"error": "Watchlist not found"}), 404

        if not current.get("cpes"):
            return jsonify({"error": "No CPEs in watchlist"}), 400

        # Determine time window
        if win == "7d":
            force_since = now_utc() - timedelta(days=7)
        elif win == "14d":
            force_since = now_utc() - timedelta(days=14)
        elif win == "30d":
            force_since = now_utc() - timedelta(days=30)
        elif win == "90d":
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)
        else:
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)

        options = current.get("options", {})
        sources = normalize_sources(options.get("sources"))
        session_obj = build_session(
            https_proxy=options.get("httpsProxy") or args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=options.get("httpProxy") or args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=options.get("caBundle") or args.ca_bundle,
            insecure=options.get("insecure", False) or args.insecure,
            timeout=int(options.get("timeout") or args.timeout or 60),
        )
        state_all = load_json(STATE_FILE, {})
        state_key = f"vuln:{hash_for_cpes(current['cpes'])}"
        results, updated_entry = run_scan(
            cpes=current["cpes"],
            state_all=state_all,
            state_key=state_key,
            session=session_obj,
            insecure=options.get("insecure", False) or args.insecure,
            since=force_since,
            kev_only=options.get("hasKev", False),
            sources=sources,
        )
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)

        # Mark new vulnerabilities
        new_cve_ids = set()
        new_vulns = get_new_vulnerabilities(results, watchlist_id)
        new_cve_ids = {v["cve"] for v in new_vulns}

        # Add to scan history
        add_scan_result(
            watchlist_id=watchlist_id,
            watchlist_name=current.get("name", "Unnamed"),
            cpes=current["cpes"],
            cve_records=results,
            scan_window=win
        )

        # Transform results for frontend
        formatted_results = []
        for r in results:
            cvss_score = r.get("score")
            if cvss_score is None:
                cvss_score = (r.get("metrics") or {}).get("baseScore")
            severity = r.get("severity")
            if not severity:
                severity = (r.get("metrics") or {}).get("baseSeverity")
            formatted_results.append({
                "id": r.get("cve"),
                "cve": r.get("cve"),
                "published": r.get("published"),
                "lastModified": r.get("lastModified"),
                "sourceIdentifier": r.get("sourceIdentifier"),
                "kev": r.get("kev", False),
                "kev_data": r.get("kev_data", {}),
                "epss": r.get("epss"),
                "epss_percentile": r.get("epss_percentile"),
                "cvssScore": cvss_score,
                "severity": severity,
                "description": r.get("description"),
                "cwes": r.get("cwes", []),
                "refs": r.get("refs", []),
                "references": r.get("refs", []),
                "matchedCPE": [r.get("matched_cpe_query")] if r.get("matched_cpe_query") else [],
                "is_new": r.get("cve") in new_cve_ids,
            })

        window_labels = {
            "7d": "last 7 days",
            "14d": "last 14 days",
            "30d": "last 30 days",
            "90d": "last 90 days",
            "24h": "last 24 hours",
        }
        window_label = window_labels.get(win, "last 24 hours")

        return jsonify({
            "results": formatted_results,
            "windowLabel": window_label,
            "count": len(formatted_results),
        })

    @app.post("/api/quick-scan")
    def api_quick_scan():
        """Run a quick scan without saving to watchlist."""
        if not check_csrf():
            return jsonify({"error": "Invalid CSRF token"}), 403
        data = request.get_json() or {}
        cpes_raw = data.get("cpes", [])
        win = (data.get("window") or "7d").lower()
        kev_only = data.get("kevOnly", False)
        sources = normalize_sources(data.get("sources"))

        # Parse CPEs
        if isinstance(cpes_raw, str):
            cpes = [c.strip() for c in cpes_raw.split(",") if c.strip()]
        else:
            cpes = [c.strip() for c in cpes_raw if c and c.strip()]

        if not cpes:
            return jsonify({"error": "No CPEs provided"}), 400

        # Determine time window
        if win == "24h":
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
        elif win == "7d":
            force_since = now_utc() - timedelta(days=7)
        elif win == "14d":
            force_since = now_utc() - timedelta(days=14)
        elif win == "30d":
            force_since = now_utc() - timedelta(days=30)
        elif win == "90d":
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)
        else:
            force_since = now_utc() - timedelta(days=7)

        session_obj = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=args.insecure,
            timeout=int(args.timeout or 60),
        )

        # Run scan without state tracking (quick scan doesn't persist)
        state_all = {}
        state_key = "quick_scan_temp"
        results, _ = run_scan(
            cpes=cpes,
            state_all=state_all,
            state_key=state_key,
            session=session_obj,
            insecure=args.insecure,
            since=force_since,
            kev_only=kev_only,
            sources=sources,
        )

        # Transform results for frontend
        formatted_results = []
        for r in results:
            cvss_score = r.get("score")
            if cvss_score is None:
                cvss_score = (r.get("metrics") or {}).get("baseScore")
            severity = r.get("severity")
            if not severity:
                severity = (r.get("metrics") or {}).get("baseSeverity")
            formatted_results.append({
                "id": r.get("cve"),
                "cve": r.get("cve"),
                "published": r.get("published"),
                "lastModified": r.get("lastModified"),
                "sourceIdentifier": r.get("sourceIdentifier"),
                "kev": r.get("kev", False),
                "kev_data": r.get("kev_data", {}),
                "epss": r.get("epss"),
                "epss_percentile": r.get("epss_percentile"),
                "cvssScore": cvss_score,
                "severity": severity,
                "description": r.get("description"),
                "cwes": r.get("cwes", []),
                "refs": r.get("refs", []),
                "references": r.get("refs", []),
                "matchedCPE": [r.get("matched_cpe_query")] if r.get("matched_cpe_query") else [],
                "is_new": True,  # All results are "new" for quick scan
            })

        window_labels = {
            "24h": "last 24 hours",
            "7d": "last 7 days",
            "14d": "last 14 days",
            "30d": "last 30 days",
            "90d": "last 90 days",
        }
        window_label = window_labels.get(win, "last 7 days")

        return jsonify({
            "results": formatted_results,
            "windowLabel": window_label,
            "count": len(formatted_results),
            "scannedCpes": cpes,
        })

    @app.get("/api/cpe_suggest")
    def api_cpe_suggest():
        # Simple CPE suggestion endpoint
        request.args.get("vendor", "")
        request.args.get("product", "")
        # For now, return empty suggestions - could be extended to query CPE dictionary
        return jsonify({"suggestions": []})

    # ========================================
    # Legacy form-based endpoints (backward compatibility)
    # ========================================

    @app.get("/legacy")
    def legacy_index():
        wl = read_watchlists()
        return render_legacy_template(wl["lists"], None, None, "")

    @app.get("/open/<wid>")
    def open_watchlist(wid):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        return render_legacy_template(wl["lists"], current, None, "")

    @app.post("/delete")
    def delete_lists():
        ids = (request.form.get("ids") or "").split(",")
        ids = [x for x in ids if x]
        wl = read_watchlists()
        before = len(wl["lists"])
        wl["lists"] = [x for x in wl["lists"] if x["id"] not in ids]
        write_watchlists(wl)
        flash(f"Deleted {before - len(wl['lists'])} watchlist(s).")
        return redirect(url_for("index"))

    @app.get("/delete/<wid>")
    def delete_single(wid):
        wl = read_watchlists()
        wl["lists"] = [x for x in wl["lists"] if x["id"] != wid]
        write_watchlists(wl)
        flash("Deleted.")
        return redirect(url_for("index"))

    @app.get("/run/<wid>")
    def run_watchlist(wid):
        wl = read_watchlists()
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            flash("Watchlist not found.")
            return redirect(url_for("index"))
        win = (request.args.get("win") or "24h").lower()
        if win == "24h":
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
        else:
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)

        session_obj = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=current.get("insecure", False) or args.insecure,
            timeout=args.timeout,
        )
        options = current.get("options", {}) or {}
        sources = normalize_sources(options.get("sources"))
        state_all = load_json(STATE_FILE, {})
        state_key = f"vuln:{hash_for_cpes(current['cpes'])}"
        results, updated_entry = run_scan(
            cpes=current["cpes"],
            state_all=state_all,
            state_key=state_key,
            session=session_obj,
            insecure=current.get("insecure", False) or args.insecure,
            since=force_since,
            kev_only=False,
            sources=sources,
        )
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)

        # Mark new vulnerabilities
        new_cve_ids = set()
        if wl_id := current.get("id"):
            new_vulns = get_new_vulnerabilities(results, wl_id)
            new_cve_ids = {v["cve"] for v in new_vulns}
            add_scan_result(
                watchlist_id=wl_id,
                watchlist_name=current.get("name", "Unnamed"),
                cpes=current["cpes"],
                cve_records=results,
                scan_window=win
            )

        for result in results:
            result["is_new"] = result["cve"] in new_cve_ids

        window_label = "last 24 hours" if win == "24h" else "last 90 days"
        return render_legacy_template(wl["lists"], current, results, window_label)

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
        entry = {"id": wid, "name": name or f"List {len(wl['lists'])+1}", "cpes": cpes, "insecure": insecure_flag}
        wl["lists"].insert(0, entry)
        write_watchlists(wl)

        if action == "save_only":
            flash("Saved.")
            return redirect(url_for("open_watchlist", wid=wid))
        next_window = "24h" if action == "run_daily" else "90d"
        return redirect(url_for("run_watchlist", wid=wid, win=next_window))

    # Export helpers
    def _scan_for_export(wid: str, win: str):
        wl = load_json(WATCHLISTS_FILE, {"lists": []})
        current = next((x for x in wl["lists"] if x["id"] == wid), None)
        if not current:
            return None, None
        if win == "24h":
            force_since = now_utc() - timedelta(hours=DAILY_LOOKBACK_HOURS)
        else:
            force_since = now_utc() - timedelta(days=LONG_BACKFILL_DAYS)
        session_obj = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=current.get("insecure", False) or args.insecure,
            timeout=args.timeout,
        )
        options = current.get("options", {}) or {}
        sources = normalize_sources(options.get("sources"))
        state_all = load_json(STATE_FILE, {})
        state_key = f"vuln:{hash_for_cpes(current['cpes'])}"
        results, updated_entry = run_scan(
            cpes=current["cpes"],
            state_all=state_all,
            state_key=state_key,
            session=session_obj,
            insecure=current.get("insecure", False) or args.insecure,
            since=force_since,
            kev_only=False,
            sources=sources,
        )
        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            save_json(STATE_FILE, state_all)
        return current, results

    @app.get("/export/<wid>.json")
    def export_json(wid):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current:
            return Response("Not found", status=404)
        body = json.dumps(results, ensure_ascii=False, indent=2)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{current["name"]}_{win}.json"'})

    @app.get("/export/<wid>.csv")
    def export_csv(wid):
        win = (request.args.get("win") or "24h").lower()
        current, results = _scan_for_export(wid, win)
        if not current:
            return Response("Not found", status=404)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([
            "CVE", "Severity", "CVSS_Score", "EPSS_Score", "EPSS_Percentile",
            "Published", "LastModified", "MatchedCPE", "KEV", "CWEs", "Description",
        ])
        for r in results:
            w.writerow([
                r.get("cve", ""),
                r.get("severity", ""),
                r.get("score", ""),
                r.get("epss", ""),
                r.get("epss_percentile", ""),
                r.get("published", ""),
                r.get("lastModified", ""),
                r.get("matched_cpe_query", ""),
                "yes" if r.get("kev") else "",
                ";".join(r.get("cwes", [])),
                (r.get("description", "") or "").replace("\n", " ").strip(),
            ])
        body = buf.getvalue()
        return Response(body, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{current["name"]}_{win}.csv"'})

    def render_legacy_template(watchlists, current, results, window_label):
        # Kept for backward compatibility - returns legacy HTML
        return redirect(url_for("index"))

    return app
