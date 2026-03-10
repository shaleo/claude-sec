from pathlib import Path

import pytest

from claude_sec.config_reader import read_settings, read_mcp_config, read_all_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_read_valid_settings():
    cfg = read_settings(FIXTURES / "user" / "settings.json")
    assert "permissions" in cfg
    assert "Bash(git status)" in cfg["permissions"]["allow"]


def test_read_missing_file():
    cfg = read_settings(FIXTURES / "nonexistent.json")
    assert cfg == {}


def test_read_malformed_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid json")
    with pytest.raises(ValueError, match="Failed to parse"):
        read_settings(bad)


def test_read_mcp_config():
    cfg = read_mcp_config(FIXTURES / "user" / "mcp.json")
    assert "chrome-devtools" in cfg
    assert "@latest" in str(cfg["chrome-devtools"]["args"])


def test_read_mcp_missing():
    cfg = read_mcp_config(FIXTURES / "nonexistent.json")
    assert cfg == {}


def test_read_all_config_merges():
    raw = read_all_config(
        project_dir=FIXTURES / "project",
        user_dir=FIXTURES / "user",
    )
    # Should have merged settings
    assert "settings" in raw
    assert "mcp_servers" in raw
    assert "hooks" in raw
    # Project settings should be present
    assert raw["settings"]["project"] is not None
    # MCP servers from both user and project
    assert "chrome-devtools" in raw["mcp_servers"]
    assert "project-server" in raw["mcp_servers"]


def test_read_all_config_missing_project():
    raw = read_all_config(
        project_dir=Path("/nonexistent"),
        user_dir=FIXTURES / "user",
    )
    assert raw["settings"]["user"] is not None
    assert raw["settings"]["project"] == {}
    assert raw["settings"]["local"] == {}
