import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import utils


def test_hash_for_cpes_is_order_insensitive():
    values = ["cpe:2.3:a:one:prod:1:*:*:*:*:*:*:*", "cpe:2.3:a:two:prod:1:*:*:*:*:*:*:*"]
    a = utils.hash_for_cpes(values)
    b = utils.hash_for_cpes(reversed(values))
    assert a == b


def test_read_cpes_file(tmp_path):
    content = """
    # comment line
    cpe:2.3:a:one:prod:1:*:*:*:*:*:*:*, cpe:2.3:a:two:prod:1:*:*:*:*:*:*:*
    cpe:2.3:a:three:prod:1:*:*:*:*:*:*:*
    """
    path = tmp_path / "cpes.txt"
    path.write_text(content)
    values = utils.read_cpes_file(path)
    assert "cpe:2.3:a:one:prod:1:*:*:*:*:*:*:*" in values
    assert "cpe:2.3:a:three:prod:1:*:*:*:*:*:*:*" in values
    assert len(values) == 3


def test_has_specific_version():
    assert utils.has_specific_version("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*") is True
    assert utils.has_specific_version("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*") is False


def test_chunk_windows_respects_limit():
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 1, 15, tzinfo=timezone.utc)
    windows = list(utils.chunk_windows(start, end, 7))
    assert windows[0][0] == start
    assert windows[-1][1] == end
    assert all((b - a).days <= 7 for a, b in windows)


def test_parse_iso_round_trip():
    now = datetime(2024, 5, 1, 12, 30, 0, tzinfo=timezone.utc)
    text = utils.iso(now)
    parsed = utils.parse_iso(text)
    assert parsed == now


def test_load_json_returns_default_on_error(tmp_path):
    path = tmp_path / "data.json"
    path.write_text("not json")
    default = {"hello": "world"}
    assert utils.load_json(path, default) == default
    assert utils.load_json(tmp_path / "missing.json", default) == default


def test_save_json_writes_file(tmp_path):
    path = tmp_path / "state.json"
    utils.save_json(path, {"a": 1})
    data = json.loads(path.read_text())
    assert data == {"a": 1}
