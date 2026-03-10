from claude_sec.analyzers.network import analyze_network
from claude_sec.models import Severity


def _config_with_network(allowed_hosts=None, mcp_servers=None, extra_settings=None, project_mcp=None):
    settings = {}
    if allowed_hosts is not None:
        settings = {"sandbox": {"network": {"allowedHosts": allowed_hosts}}}
    if extra_settings:
        settings.update(extra_settings)
    return {
        "settings": {"user": settings, "project": {}, "local": {}},
        "mcp_servers": mcp_servers or {},
        "_project_mcp_servers": project_mcp or {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }


def test_only_anthropic_host():
    config = _config_with_network(allowed_hosts=["anthropic.com"])
    findings = analyze_network(config)
    # Should have no HIGH/CRITICAL findings about hosts
    host_findings = [f for f in findings if f.severity >= Severity.HIGH and "host" in f.title.lower()]
    assert len(host_findings) == 0


def test_wildcard_host():
    config = _config_with_network(allowed_hosts=["*"])
    findings = analyze_network(config)
    high = [f for f in findings if f.severity >= Severity.HIGH]
    assert any("wildcard" in f.title.lower() or "broad" in f.title.lower() for f in high)


def test_many_hosts():
    config = _config_with_network(allowed_hosts=["anthropic.com", "github.com", "npmjs.org", "pypi.org", "example.com"])
    findings = analyze_network(config)
    medium = [f for f in findings if f.severity >= Severity.MEDIUM and "host" in f.title.lower()]
    assert len(medium) > 0


def test_unpinned_mcp_version():
    config = _config_with_network(
        allowed_hosts=["anthropic.com"],
        mcp_servers={"test": {"command": "npx", "args": ["some-pkg@latest"]}}
    )
    findings = analyze_network(config)
    assert any("unpinned" in f.title.lower() or "pin" in f.description.lower() for f in findings)


def test_pinned_mcp_version():
    config = _config_with_network(
        allowed_hosts=["anthropic.com"],
        mcp_servers={"test": {"command": "npx", "args": ["some-pkg@1.2.3"]}}
    )
    findings = analyze_network(config)
    unpinned = [f for f in findings if "unpinned" in f.title.lower()]
    assert len(unpinned) == 0


def test_no_mcp_servers():
    config = _config_with_network(allowed_hosts=["anthropic.com"], mcp_servers={})
    findings = analyze_network(config)
    info = [f for f in findings if f.severity == Severity.INFO and "mcp" in f.title.lower()]
    assert len(info) > 0


def test_no_network_config():
    config = _config_with_network()
    findings = analyze_network(config)
    assert any("network" in f.title.lower() or "sandbox" in f.description.lower() for f in findings)


def test_enable_all_project_mcp_servers():
    config = _config_with_network(allowed_hosts=["anthropic.com"])
    config["settings"]["user"]["enableAllProjectMcpServers"] = True
    findings = analyze_network(config)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("all project mcp" in f.title.lower() for f in critical)


def test_weaker_network_isolation():
    config = _config_with_network(allowed_hosts=["anthropic.com"])
    config["settings"]["user"]["sandbox"]["network"]["enableWeakerNetworkIsolation"] = True
    findings = analyze_network(config)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert any("weaker network" in f.title.lower() for f in high)


def test_project_mcp_servers_flagged():
    config = _config_with_network(
        allowed_hosts=["anthropic.com"],
        mcp_servers={"proj-server": {"command": "node", "args": ["server.js"]}},
        project_mcp={"proj-server": {"command": "node", "args": ["server.js"]}},
    )
    findings = analyze_network(config)
    proj_mcp = [f for f in findings if "project config" in f.title.lower() or "project .mcp" in f.description.lower()]
    assert len(proj_mcp) > 0
