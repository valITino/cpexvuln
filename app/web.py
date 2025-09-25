"""Web UI for the CPE watch application.
Drop-in replacement with:
- Defensive handling of scan return types (prevents "'list' object has no attribute 'get'")
- Consistent API error responses
- CSV/JSON export unchanged
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    session,
)
from werkzeug.exceptions import HTTPException

from .config import (
    DAILY_LOOKBACK_HOURS,
    EXTENDED_LOOKBACK_DAYS,
    LONG_BACKFILL_DAYS,
    STATE_FILE,
    WATCHLISTS_FILE,
)
from .nvd import build_session, iter_cpe_products
from .scan import run_scan
from .utils import (
    default_project,
    hash_for_cpes,
    has_specific_version,
    is_valid_cpe,
    iso,
    load_json,
    migrate_watchlists,
    normalize_watchlist_options,
    now_utc,
    save_json,
)


logger = logging.getLogger(__name__)


QUERY_PARAM_KEYS = (
    "cveId",
    "cweId",
    "cvssV3Severity",
    "cvssV4Severity",
    "cvssV3Metrics",
    "cvssV4Metrics",
)


def create_app(args) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )
    app.secret_key = "dev-" + uuid.uuid4().hex
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

    def wants_json_response() -> bool:
        return request.path.startswith("/api/")

    @app.errorhandler(HTTPException)
    def _handle_http_exception(exc: HTTPException):
        if wants_json_response():
            logger.warning("API error on %s: %s", request.path, exc.description)
            return json_response({"error": exc.description or exc.name}, status=exc.code)
        return exc

    @app.errorhandler(Exception)
    def _handle_generic_exception(exc: Exception):
        logger.exception("Unhandled error on %s", request.path)
        if wants_json_response():
            return json_response({"error": "Internal server error"}, status=500)
        raise exc

    # ------------------------------------------------------------------ helpers

    def _csrf_token() -> str:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_hex(16)
            session["_csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = _csrf_token

    @app.before_request
    def _csrf_protect() -> None:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            token = request.headers.get("X-CSRF-Token")
            if not token and request.form:
                token = request.form.get("csrf_token")
            if not token or token != session.get("_csrf_token"):
                abort(400, "Invalid CSRF token")

    def read_watchlists() -> Dict[str, Any]:
        raw = load_json(WATCHLISTS_FILE, {})
        migrated = migrate_watchlists(raw)
        if migrated != raw:
            save_json(WATCHLISTS_FILE, migrated)
        return migrated

    def write_watchlists(data: Dict[str, Any]) -> None:
        data["projects"].sort(key=lambda proj: proj.get("order", 0))
        data["lists"].sort(key=lambda item: (item.get("projectId"), item.get("order", 0)))
        save_json(WATCHLISTS_FILE, data)

    def find_project(data: Dict[str, Any], project_id: str) -> Optional[Dict[str, Any]]:
        return next((p for p in data.get("projects", []) if p["id"] == project_id), None)

    def find_watchlist(data: Dict[str, Any], watch_id: str) -> Optional[Dict[str, Any]]:
        return next((w for w in data.get("lists", []) if w["id"] == watch_id), None)

    def resequence_project(data: Dict[str, Any], project_id: str) -> None:
        items = [w for w in data.get("lists", []) if w["projectId"] == project_id]
        items.sort(key=lambda entry: entry.get("order", 0))
        for idx, item in enumerate(items):
            item["order"] = idx

    def parse_cpes(raw: Any) -> List[str]:
        values: List[str] = []
        if isinstance(raw, str):
            pieces = [seg.strip() for seg in raw.split(",")]
        elif isinstance(raw, list):
            pieces = []
            for entry in raw:
                if isinstance(entry, str):
                    pieces.extend([seg.strip() for seg in entry.split(",")])
        else:
            pieces = []
        for item in pieces:
            if item and item not in values:
                values.append(item)
        return values

    def validate_cpes(cpes: List[str], is_vulnerable: bool) -> List[str]:
        warnings: List[str] = []
        if not cpes:
            abort(400, "At least one CPE is required")
        for cpe in cpes:
            if not is_valid_cpe(cpe):
                abort(400, f"Invalid CPE string: {cpe}")
            if is_vulnerable and not has_specific_version(cpe):
                warning = (
                    "Using isVulnerable=true with wildcard versions may return 400 from NVD."
                )
                if warning not in warnings:
                    warnings.append(warning)
        return warnings

    def apply_watchlist_changes(
        data: Dict[str, Any],
        entry: Dict[str, Any],
        payload: Dict[str, Any],
    ) -> List[str]:
        warnings: List[str] = []
        name = payload.get("name")
        if name is not None:
            entry["name"] = name.strip() or entry.get("name") or "Untitled"

        if "projectId" in payload:
            project_id = payload["projectId"]
            if project_id and not find_project(data, project_id):
                abort(400, "Unknown project")
            if project_id:
                entry["projectId"] = project_id

        options_payload = dict(payload.get("options") or {})
        current_options = dict(entry.get("options") or {})
        api_key_val = options_payload.pop("apiKey", None)
        if api_key_val is not None:
            if isinstance(api_key_val, str):
                api_key_val = api_key_val.strip()
            if api_key_val == "":
                current_options["apiKey"] = None
            elif api_key_val is not None:
                current_options["apiKey"] = api_key_val
        options_payload.pop("hasApiKey", None)
        for key, value in options_payload.items():
            current_options[key] = value
        entry["options"] = normalize_watchlist_options(current_options)

        if "cpes" in payload:
            cpes = parse_cpes(payload["cpes"])
            warnings.extend(
                validate_cpes(cpes, entry["options"].get("isVulnerable", False))
            )
            entry["cpes"] = cpes
        else:
            warnings.extend(
                validate_cpes(entry.get("cpes", []), entry["options"].get("isVulnerable", False))
            )

        if "order" in payload:
            try:
                entry["order"] = int(payload["order"])
            except (TypeError, ValueError):
                pass

        return warnings

    def serialize_watchlist(entry: Dict[str, Any]) -> Dict[str, Any]:
        options = dict(entry.get("options") or {})
        has_key = bool(options.get("apiKey"))
        options_safe = dict(options)
        options_safe.pop("apiKey", None)
        options_safe["hasApiKey"] = has_key
        return {
            "id": entry["id"],
            "name": entry["name"],
            "projectId": entry["projectId"],
            "cpes": entry.get("cpes", []),
            "order": entry.get("order", 0),
            "options": options_safe,
        }

    def serialize_project(entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": entry["id"],
            "name": entry["name"],
            "order": entry.get("order", 0),
        }

    def build_session_for(entry: Dict[str, Any]):
        options = normalize_watchlist_options(entry.get("options"))
        session_obj = build_session(
            https_proxy=options.get("httpsProxy") or args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=options.get("httpProxy") or args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=options.get("caBundle") or args.ca_bundle,
            insecure=bool(options.get("insecure")) or args.insecure,
            timeout=options.get("timeout") or args.timeout,
        )
        state_all = load_json(STATE_FILE, {})
        state_key = f"nvd:{entry['projectId']}:{hash_for_cpes(entry['cpes'])}"
        api_key = options.get("apiKey") or args.nvd_api_key
        return session_obj, state_all, state_key, options, api_key

    def compute_window(window: str) -> Tuple[str, Any]:
        win = (window or "24h").lower()
        now = now_utc()
        if win == "24h":
            return "last 24 hours", now - timedelta(hours=DAILY_LOOKBACK_HOURS)
        if win == "120d":
            return "last 120 days", now - timedelta(days=EXTENDED_LOOKBACK_DAYS)
        return "last 90 days", now - timedelta(days=LONG_BACKFILL_DAYS)

    def run_watch(entry: Dict[str, Any], window: str):
        label, since = compute_window(window)
        session_obj, state_all, state_key, options, api_key = build_session_for(entry)
        query_params: Dict[str, Any] = {}
        for key in QUERY_PARAM_KEYS:
            value = options.get(key)
            if value:
                query_params[key] = value
        if options.get("hasKev"):
            query_params["hasKev"] = "true"
        logger.info(
            "Running watchlist %s (%s) for %s",
            entry.get("id"),
            entry.get("name"),
            label,
        )
        try:
            results, updated_entry, issues = run_scan(
                cpes=entry["cpes"],
                state_all=state_all,
                state_key=state_key,
                session=session_obj,
                insecure=bool(options.get("insecure")) or args.insecure,
                api_key=api_key,
                since=since,
                no_rejected=options.get("noRejected", True),
                kev_only=False,
                min_score=None,
                is_vulnerable=options.get("isVulnerable", False),
                extra_params=query_params,
            )
        except Exception as exc:  # defensive guard
            logger.exception(
                "Scan failed for watchlist %s (%s)", entry.get("id"), entry.get("name")
            )
            abort(502, f"Scan failed: {exc}")

        # --- Defensive guards to prevent AttributeError on unexpected shapes ---
        if not isinstance(updated_entry, dict):
            updated_entry = {}
        if not isinstance(issues, list):
            issues = []

        if updated_entry.get("per_cpe"):
            state_all[state_key] = updated_entry
            proj_state = state_all.setdefault("projects", {})
            proj_state[entry["projectId"]] = iso(now_utc())
            save_json(STATE_FILE, state_all)

        detailed_issues: List[Dict[str, Any]] = []
        for issue in issues or []:
            # Ensure each issue is at least a dict
            if not isinstance(issue, dict):
                issue = {"message": str(issue)}
            item = {
                "cpe": issue.get("cpe"),
                "message": issue.get("message") or "Unknown error",
                "watchlistId": entry.get("id"),
                "watchlistName": entry.get("name"),
                "window": label,
            }
            detailed_issues.append(item)
            logger.warning(
                "Watchlist %s (%s) encountered an issue for %s: %s",
                entry.get("id"),
                entry.get("name"),
                item.get("cpe"),
                item.get("message"),
            )
        return results, label, detailed_issues

    def bootstrap_payload(
        data: Dict[str, Any],
        current_id: Optional[str] = None,
        results=None,
        window_label: str = "",
        issues: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        return {
            "projects": [serialize_project(p) for p in data.get("projects", [])],
            "lists": [serialize_watchlist(w) for w in data.get("lists", [])],
            "currentWatchId": current_id,
            "results": results,
            "windowLabel": window_label,
            "csrfToken": _csrf_token(),
            "issues": issues or [],
        }

    def json_response(data: Dict[str, Any], status: int = 200):
        resp = jsonify(data)
        resp.status_code = status
        return resp

    # -------------------------------------------------------------------- routes

    @app.get("/favicon.ico")
    def favicon() -> Tuple[str, int]:
        return "", 204

    @app.get("/")
    def index():
        data = read_watchlists()
        watch_id = request.args.get("watch")
        results = None
        label = ""
        issues: List[Dict[str, Any]] = []
        if watch_id:
            entry = find_watchlist(data, watch_id)
            if entry:
                results, label, issues = run_watch(entry, request.args.get("win", "24h"))
        return render_template(
            "index.html",
            bootstrap=bootstrap_payload(
                data,
                watch_id if results else None,
                results,
                label,
                issues,
            ),
        )

    @app.get("/api/watchlists")
    def api_watchlists():
        data = read_watchlists()
        return json_response({
            "projects": [serialize_project(p) for p in data.get("projects", [])],
            "lists": [serialize_watchlist(w) for w in data.get("lists", [])],
        })

    @app.post("/api/projects")
    def api_create_project():
        data = read_watchlists()
        payload = request.get_json(force=True) or {}
        name = (payload.get("name") or "New Project").strip() or "New Project"
        order = max((p.get("order", 0) for p in data.get("projects", [])), default=-1) + 1
        project = {"id": uuid.uuid4().hex, "name": name, "order": order}
        data.setdefault("projects", []).append(project)
        write_watchlists(data)
        return json_response({"project": serialize_project(project)}, status=201)

    @app.patch("/api/projects/<pid>")
    def api_rename_project(pid: str):
        data = read_watchlists()
        project = find_project(data, pid)
        if not project:
            abort(404, "Project not found")
        payload = request.get_json(force=True) or {}
        name = payload.get("name")
        if name is None:
            abort(400, "Missing name")
        project["name"] = name.strip() or project["name"]
        write_watchlists(data)
        return json_response({"project": serialize_project(project)})

    @app.delete("/api/projects/<pid>")
    def api_delete_project(pid: str):
        data = read_watchlists()
        project = find_project(data, pid)
        if not project:
            abort(404, "Project not found")
        if any(w for w in data.get("lists", []) if w["projectId"] == pid):
            abort(400, "Cannot delete a non-empty project")
        data["projects"] = [p for p in data["projects"] if p["id"] != pid]
        if not data["projects"]:
            data["projects"].append(default_project(order=0))
        write_watchlists(data)
        return json_response({"ok": True})

    @app.get("/api/projects/<pid>/export")
    def api_export_project(pid: str):
        data = read_watchlists()
        project = find_project(data, pid)
        if not project:
            abort(404, "Project not found")
        lists = [serialize_watchlist(w) for w in data.get("lists", []) if w["projectId"] == pid]
        body = json.dumps({"project": serialize_project(project), "lists": lists}, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="project_{project["name"]}.json"'},
        )

    @app.post("/api/projects/<pid>/import")
    def api_import_project(pid: str):
        data = read_watchlists()
        project = find_project(data, pid)
        if not project:
            abort(404, "Project not found")
        payload = request.get_json(force=True) or {}
        lists = payload.get("lists") or []
        if not isinstance(lists, list):
            abort(400, "Invalid payload")
        existing = {w["name"].lower(): w for w in data.get("lists", []) if w["projectId"] == pid}
        warnings: List[str] = []
        for item in lists:
            if not isinstance(item, dict):
                continue
            name = (item.get("name") or "Imported").strip() or "Imported"
            target = existing.get(name.lower())
            if target:
                warnings.extend(apply_watchlist_changes(data, target, item))
            else:
                next_order = max(
                    (w.get("order", 0) for w in data.get("lists", []) if w["projectId"] == pid),
                    default=-1,
                ) + 1
                new_entry = {
                    "id": uuid.uuid4().hex,
                    "name": name,
                    "projectId": pid,
                    "cpes": [],
                    "options": normalize_watchlist_options({}),
                    "order": next_order,
                }
                warnings.extend(apply_watchlist_changes(data, new_entry, item))
                data["lists"].append(new_entry)
        resequence_project(data, pid)
        write_watchlists(data)
        return json_response({
            "projects": [serialize_project(p) for p in data.get("projects", [])],
            "lists": [serialize_watchlist(w) for w in data.get("lists", [])],
            "warnings": warnings,
        })

    @app.post("/api/watchlists")
    def api_create_watchlist():
        data = read_watchlists()
        payload = request.get_json(force=True) or {}
        project_id = payload.get("projectId") or (data.get("projects") or [default_project()])[0]["id"]
        if not find_project(data, project_id):
            abort(400, "Unknown project")
        next_order = max(
            (w.get("order", 0) for w in data.get("lists", []) if w["projectId"] == project_id),
            default=-1,
        ) + 1
        entry = {
            "id": uuid.uuid4().hex,
            "name": (payload.get("name") or "New Watchlist").strip() or "New Watchlist",
            "projectId": project_id,
            "cpes": [],
            "options": normalize_watchlist_options({}),
            "order": next_order,
        }
        warnings = apply_watchlist_changes(data, entry, payload)
        data.setdefault("lists", []).append(entry)
        resequence_project(data, project_id)
        write_watchlists(data)
        return json_response({"watchlist": serialize_watchlist(entry), "warnings": warnings}, status=201)

    @app.put("/api/watchlists/<wid>")
    def api_update_watchlist(wid: str):
        data = read_watchlists()
        entry = find_watchlist(data, wid)
        if not entry:
            abort(404, "Watchlist not found")
        payload = request.get_json(force=True) or {}
        old_project = entry["projectId"]
        warnings = apply_watchlist_changes(data, entry, payload)
        new_project = entry["projectId"]
        resequence_project(data, old_project)
        if new_project != old_project:
            resequence_project(data, new_project)
        write_watchlists(data)
        return json_response({"watchlist": serialize_watchlist(entry), "warnings": warnings})

    @app.delete("/api/watchlists/<wid>")
    def api_delete_watchlist(wid: str):
        data = read_watchlists()
        entry = find_watchlist(data, wid)
        if not entry:
            abort(404, "Watchlist not found")
        project_id = entry["projectId"]
        data["lists"] = [w for w in data["lists"] if w["id"] != wid]
        resequence_project(data, project_id)
        write_watchlists(data)
        return json_response({"ok": True})

    @app.post("/api/watchlists/reorder")
    def api_reorder_watchlists():
        data = read_watchlists()
        payload = request.get_json(force=True) or {}
        project_id = payload.get("projectId")
        order_ids = payload.get("order") or []
        if not project_id or not isinstance(order_ids, list):
            abort(400, "Invalid payload")
        if not find_project(data, project_id):
            abort(400, "Unknown project")
        for idx, wid in enumerate(order_ids):
            entry = find_watchlist(data, wid)
            if entry and entry["projectId"] == project_id:
                entry["order"] = idx
        resequence_project(data, project_id)
        write_watchlists(data)
        return json_response(
            {
                "projects": [serialize_project(p) for p in data.get("projects", [])],
                "lists": [serialize_watchlist(w) for w in data.get("lists", [])],
            }
        )

    @app.post("/api/run")
    def api_run_watch():
        payload = request.get_json(force=True) or {}
        wid = payload.get("watchlistId")
        window = payload.get("window", "24h")
        data = read_watchlists()
        entry = find_watchlist(data, wid)
        if not entry:
            abort(404, "Watchlist not found")
        results, label, issues = run_watch(entry, window)
        return json_response({"results": results, "windowLabel": label, "issues": issues})

    @app.get("/api/cpe_suggest")
    def api_cpe_suggest():
        vendor = (request.args.get("vendor") or "").strip()
        product = (request.args.get("product") or "").strip()
        version = (request.args.get("version") or "").strip()
        keyword = (request.args.get("keyword") or "").strip()
        part = (request.args.get("part") or "*").strip() or "*"
        limit = min(max(int(request.args.get("limit", 40)), 1), 200)
        params: Dict[str, Any] = {"resultsPerPage": limit}
        if vendor or product or version:
            def esc(text: str) -> str:
                return text.replace("\\", "\\\\").replace(":", "\\:")
            v = esc(vendor) if vendor else "*"
            p = esc(product) if product else "*"
            ver = esc(version) if version else "*"
            params["cpeMatchString"] = f"cpe:2.3:{part}:{v}:{p}:{ver}:*:*:*:*:*:*"
        if keyword:
            params["keywordSearch"] = keyword
        session_obj = build_session(
            https_proxy=args.https_proxy or os.environ.get("HTTPS_PROXY"),
            http_proxy=args.http_proxy or os.environ.get("HTTP_PROXY"),
            ca_bundle=args.ca_bundle,
            insecure=args.insecure,
            timeout=args.timeout,
        )
        items: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for product_entry in iter_cpe_products(
            session_obj,
            api_key=args.nvd_api_key,
            insecure=args.insecure,
            params=params,
        ):
            cpe_info = product_entry.get("cpe") or {}
            name = cpe_info.get("cpeName")
            if not name or name in seen:
                continue
            seen.add(name)
            items.append(
                {
                    "cpeName": name,
                    "titles": cpe_info.get("titles") or [],
                    "deprecated": bool(cpe_info.get("deprecated")),
                }
            )
            if len(items) >= limit:
                break
        return json_response({"items": items})

    @app.get("/export/<wid>.json")
    def export_json(wid: str):
        data = read_watchlists()
        entry = find_watchlist(data, wid)
        if not entry:
            return Response("Not found", status=404)
        window = request.args.get("win", "24h")
        results, _, issues = run_watch(entry, window)
        if issues and not results:
            return Response(
                "Scan failed: see server logs for details",
                status=502,
                mimetype="text/plain",
            )
        body = json.dumps(results, indent=2, ensure_ascii=False)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{entry["name"]}_{window}.json"'},
        )

    @app.get("/export/<wid>.csv")
    def export_csv(wid: str):
        data = read_watchlists()
        entry = find_watchlist(data, wid)
        if not entry:
            return Response("Not found", status=404)
        window = request.args.get("win", "24h")
        results, _, issues = run_watch(entry, window)
        if issues and not results:
            return Response(
                "Scan failed: see server logs for details",
                status=502,
                mimetype="text/plain",
            )
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
        for item in results:
            writer.writerow(
                [
                    item.get("id", ""),
                    item.get("cvssSeverity", ""),
                    item.get("cvssScore", ""),
                    item.get("published", ""),
                    item.get("lastModified", ""),
                    ";".join(item.get("matchedCPE", []) or []),
                    "yes" if item.get("kev") else "",
                    ";".join(item.get("cwes", [])),
                    (item.get("description", "") or "").replace("\n", " ").strip(),
                ]
            )
        body = buf.getvalue()
        return Response(
            body,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{entry["name"]}_{window}.csv"'},
        )

    return app
