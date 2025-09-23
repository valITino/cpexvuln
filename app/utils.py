# app/utils.py
from __future__ import annotations

import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, List, Tuple

# --- time helpers -------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    """Return NVD-friendly ISO with millis and trailing Z (UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

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

def has_specific_version(cpe_23: str) -> bool:
    """
    True only if the CPE has a concrete version.
    CPE 2.3 fields: part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    Index 5 is 'version'. Treat '*', '' and '-' as NOT specific.
    """
    parts = cpe_23.split(":")
    if len(parts) < 6:
        return False
    version = parts[5]
    return version not in ("*", "", "-")

# --- date range chunking ------------------------------------------------------

def chunk_windows(start: datetime, end: datetime, max_days: int) -> Iterable[Tuple[datetime, datetime]]:
    """Yield [start, end] windows sliced by max_days (NVD limit is 120 days)."""
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=max_days), end)
        yield (cur, nxt)
        cur = nxt