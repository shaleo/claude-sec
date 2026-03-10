from pathlib import Path

import pytest

from claude_sec.config_reader import read_all_config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_config():
    return read_all_config(
        project_dir=FIXTURES / "project",
        user_dir=FIXTURES / "user",
    )


@pytest.fixture
def empty_config():
    return {
        "settings": {"user": {}, "project": {}, "local": {}},
        "mcp_servers": {},
        "_project_mcp_servers": {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/empty",
    }
