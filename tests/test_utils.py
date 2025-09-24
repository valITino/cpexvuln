import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import utils


def test_parse_cpe23_handles_escape_and_specific_version():
    cpe = "cpe:2.3:a:example:prod\\:name:1.2.3:*:*:*:*:*:*:*"
    parsed = utils.parse_cpe23(cpe)
    assert parsed["product"] == "prod:name"
    assert parsed["version"] == "1.2.3"
    assert utils.has_specific_version(cpe) is True
    assert utils.is_valid_cpe(cpe) is True


def test_parse_cpe23_invalid():
    with pytest.raises(ValueError):
        utils.parse_cpe23("not-a-cpe")
    assert utils.is_valid_cpe("not-a-cpe") is False


def test_migrate_watchlists_adds_default_project(tmp_path, monkeypatch):
    data = {"lists": [{"id": "1", "name": "Test", "cpes": ["cpe:2.3:a:foo:bar:1:*:*:*:*:*:*:*"]}]}
    migrated = utils.migrate_watchlists(data)
    assert migrated["projects"]
    project_id = migrated["projects"][0]["id"]
    assert migrated["lists"][0]["projectId"] == project_id
