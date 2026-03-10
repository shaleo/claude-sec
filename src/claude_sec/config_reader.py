import json
from pathlib import Path
from typing import Any

RawConfig = dict[str, Any]


def read_settings(path: Path) -> dict:
    """Read a JSON settings file. Returns {} if missing."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse {path}: {e}") from e


def read_mcp_config(path: Path) -> dict:
    """Read MCP config file, returning the mcpServers dict. Returns {} if missing."""
    raw = read_settings(path)
    return raw.get("mcpServers", {})


def read_all_config(
    project_dir: Path,
    user_dir: Path | None = None,
) -> RawConfig:
    """Read all Claude config files and return a unified RawConfig dict."""
    if user_dir is None:
        user_dir = Path.home() / ".claude"

    user_settings = read_settings(user_dir / "settings.json")
    project_settings = read_settings(project_dir / ".claude" / "settings.json")
    local_settings = read_settings(project_dir / ".claude" / "settings.local.json")

    user_mcp = read_mcp_config(user_dir / "mcp.json")
    project_mcp = read_mcp_config(project_dir / ".mcp.json")

    # Merge MCP servers (project overrides user)
    all_mcp = {**user_mcp, **project_mcp}

    # Track project MCP separately for supply chain analysis
    project_mcp_servers = project_mcp

    # Extract hooks from all settings layers
    hooks = {}
    for layer in [user_settings, project_settings, local_settings]:
        hooks.update(layer.get("hooks", {}))

    # Collect paths that were scanned
    paths_scanned = []
    for p in [
        user_dir / "settings.json",
        project_dir / ".claude" / "settings.json",
        project_dir / ".claude" / "settings.local.json",
        user_dir / "mcp.json",
        project_dir / ".mcp.json",
    ]:
        paths_scanned.append(str(p))

    return {
        "settings": {
            "user": user_settings,
            "project": project_settings,
            "local": local_settings,
        },
        "mcp_servers": all_mcp,
        "_project_mcp_servers": project_mcp_servers,
        "hooks": hooks,
        "paths_scanned": paths_scanned,
        "project_dir": str(project_dir),
    }
