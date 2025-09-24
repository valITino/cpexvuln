# app/utils.py
from __future__ import annotations

import json
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# CPE components (excluding the ``cpe:2.3`` prefix)
_CPE_ATTRS = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
]

DEFAULT_WATCHLIST_OPTIONS: Dict[str, Any] = {
    "noRejected": True,
    "isVulnerable": False,
    "insecure": False,
    "minCvss": 0.0,
    "timeout": None,
    "apiKey": None,
    "httpProxy": None,
    "httpsProxy": None,
    "caBundle": None,
    "hasKev": False,
    "cveId": None,
    "cweId": None,
    "cvssV3Severity": None,
    "cvssV4Severity": None,
    "cvssV3Metrics": None,
    "cvssV4Metrics": None,
}


def default_project(order: int = 0) -> Dict[str, Any]:
    return {"id": uuid.uuid4().hex, "name": "Default", "order": order}


def _sanitize_option_value(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return value


def normalize_watchlist_options(data: Dict[str, Any] | None) -> Dict[str, Any]:
    options: Dict[str, Any] = {}
    src = data or {}
    for key, default in DEFAULT_WATCHLIST_OPTIONS.items():
        if key in src:
            options[key] = _sanitize_option_value(src[key])
        else:
            options[key] = default
    # Booleans may come back as strings from form submissions
    options["noRejected"] = bool(options.get("noRejected", True))
    options["isVulnerable"] = bool(options.get("isVulnerable", False))
    options["insecure"] = bool(options.get("insecure", False))
    options["hasKev"] = bool(options.get("hasKev", False))
    try:
        options["minCvss"] = float(options.get("minCvss", 0.0) or 0.0)
    except (TypeError, ValueError):
        options["minCvss"] = 0.0
    if options.get("timeout"):
        try:
            timeout_val = int(options["timeout"])
            options["timeout"] = max(timeout_val, 1)
        except (TypeError, ValueError):
            options["timeout"] = None
    else:
        options["timeout"] = None
    for proxy_key in ("httpProxy", "httpsProxy", "caBundle", "apiKey"):
        options[proxy_key] = _sanitize_option_value(options.get(proxy_key))
    return options


def migrate_watchlists(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return watchlist data conforming to the new projects schema."""

    raw = raw or {}
    lists = list(raw.get("lists", []))
    projects = list(raw.get("projects", []))

    if not projects:
        # Old schema: create a default project and map lists to it
        proj = default_project(order=0)
        projects = [proj]
        default_pid = proj["id"]
    else:
        default_pid = projects[0].get("id") if projects else default_project(order=0)["id"]

    normalized_projects: List[Dict[str, Any]] = []
    for idx, project in enumerate(projects):
        pid = project.get("id") or uuid.uuid4().hex
        name = (project.get("name") or "Project").strip() or "Project"
        order = project.get("order", idx)
        try:
            order_int = int(order)
        except (TypeError, ValueError):
            order_int = idx
        normalized_projects.append({"id": pid, "name": name, "order": order_int})

    normalized_lists: List[Dict[str, Any]] = []
    for idx, item in enumerate(lists):
        pid = item.get("projectId") or default_pid
        wid = item.get("id") or uuid.uuid4().hex
        name = (item.get("name") or f"List {idx + 1}").strip() or f"List {idx + 1}"
        cpes_raw = item.get("cpes") or []
        cpes = [c for c in cpes_raw if isinstance(c, str) and c.strip()]
        options_data = item.get("options") or {}
        for legacy_key in ("insecure", "noRejected", "isVulnerable", "minCvss"):
            if legacy_key in item and legacy_key not in options_data:
                options_data[legacy_key] = item[legacy_key]
        normalized_lists.append(
            {
                "id": wid,
                "projectId": pid,
                "name": name,
                "cpes": cpes,
                "options": normalize_watchlist_options(options_data),
                "order": int(item.get("order", idx)),
            }
        )

    normalized_projects.sort(key=lambda p: p.get("order", 0))
    normalized_lists.sort(key=lambda item: (item.get("projectId"), item.get("order", 0)))

    return {"projects": normalized_projects, "lists": normalized_lists}

# --- time helpers -------------------------------------------------------------


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Return NVD-friendly ISO with millis and trailing Z (UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_iso(value: str) -> datetime:
    """Parse ISO timestamps emitted by NVD and return an aware ``datetime``.

    The NVD API returns timestamps with a ``Z`` suffix and optional
    millisecond precision (``%Y-%m-%dT%H:%M:%S[.fff]Z``).  We keep the parser
    lenient so that persisted state does not break if formatting changes
    slightly.  Invalid or empty strings fall back to ``now_utc()`` which keeps
    scheduling logic robust instead of raising and aborting a run.
    """

    if not value:
        return now_utc()

    text = value.strip()
    tz = timezone.utc
    if text.endswith("Z"):
        text = text[:-1]

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=tz)
        except ValueError:
            pass

    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=tz)
    except ValueError:
        return now_utc()

# --- files & json (Path-aware) ------------------------------------------------


def _p(p: os.PathLike | str) -> Path:
    return p if isinstance(p, Path) else Path(p)


def ensure_dir(path: os.PathLike | str) -> None:
    p = _p(path)
    p.mkdir(parents=True, exist_ok=True)


def load_json(path: os.PathLike | str, default: Any = None) -> Any:
    p = _p(path)
    if not p.exists():
        return {} if default is None else default
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {} if default is None else default


def save_json(path: os.PathLike | str, data: Any) -> None:
    p = _p(path)
    if p.parent:
        p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")  # e.g. state.json.tmp
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, p)  # atomic on same filesystem

# --- CPE handling -------------------------------------------------------------


def read_cpes_file(path: os.PathLike | str) -> List[str]:
    """
    Read CPEs from a file. Supports:
      - one per line (comments with '#')
      - comma-separated entries in any line
    """
    p = _p(path)
    out: List[str] = []
    with p.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [s.strip() for s in line.split(",") if s.strip()]
            out.extend(parts)
    return out


def hash_for_cpes(cpes: Iterable[str]) -> str:
    s = "\n".join(sorted(set(cpes)))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _split_cpe(value: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    esc = False
    for ch in value:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == ":":
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse_cpe23(value: str) -> Dict[str, str]:
    if not isinstance(value, str):
        raise ValueError("CPE must be a string")
    parts = _split_cpe(value)
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        raise ValueError("Invalid CPE 2.3 string")
    attrs = {}
    for idx, key in enumerate(_CPE_ATTRS, start=2):
        attrs[key] = parts[idx]
    return attrs


def unescape_cpe_component(value: str) -> str:
    if not value:
        return value
    result: List[str] = []
    esc = False
    for ch in value:
        if esc:
            result.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        else:
            result.append(ch)
    return "".join(result)


def has_specific_version(cpe_23: str) -> bool:
    try:
        version = parse_cpe23(cpe_23)["version"]
    except ValueError:
        return False
    return version not in ("*", "", "-")


def is_valid_cpe(cpe_23: str) -> bool:
    try:
        parse_cpe23(cpe_23)
        return True
    except ValueError:
        return False

# --- date range chunking ------------------------------------------------------


def chunk_windows(start: datetime, end: datetime, max_days: int) -> Iterable[Tuple[datetime, datetime]]:
    """Yield [start, end] windows sliced by max_days (NVD limit is 120 days)."""
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=max_days), end)
        yield (cur, nxt)
        cur = nxt
