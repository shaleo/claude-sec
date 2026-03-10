import re

from claude_sec.models import Finding, Severity

CATEGORY = "network"

TRUSTED_HOSTS = {"anthropic.com", "localhost", "127.0.0.1"}


def _get_allowed_hosts(config: dict) -> list[str] | None:
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        network = settings.get("sandbox", {}).get("network", {})
        if "allowedHosts" in network:
            return network["allowedHosts"]
    return None


def _is_pinned_version(arg: str) -> bool:
    """Check if an npm package arg has a pinned version (not @latest or no version)."""
    if "@" not in arg:
        return False
    version = arg.rsplit("@", 1)[-1]
    return bool(re.match(r"^\d+\.\d+", version))


def _get_setting(config: dict, key: str) -> object | None:
    """Get a top-level setting from any layer."""
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        if key in settings:
            return settings[key]
    return None


def _get_sandbox_network_setting(config: dict, key: str) -> object | None:
    """Get a sandbox.network setting from any layer."""
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        val = settings.get("sandbox", {}).get("network", {}).get(key)
        if val is not None:
            return val
    return None


def analyze_network(config: dict) -> list[Finding]:
    findings = []
    hosts = _get_allowed_hosts(config)

    if hosts is None:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title="No network sandbox configured",
            description="No network allowedHosts rules found. Network access may be unrestricted.",
            risk="Claude Code could make network requests to arbitrary hosts.",
            fix='Add "sandbox": {"network": {"allowedHosts": ["anthropic.com"]}} to settings.json',
            verification="Check settings.json for sandbox.network.allowedHosts",
        ))
    else:
        if "*" in hosts:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title="Wildcard host allowed",
                description='Network allowlist includes "*" which permits connections to any host.',
                risk="Claude Code can exfiltrate data to or fetch from any external server.",
                fix='Replace "*" with specific required hosts in sandbox.network.allowedHosts',
                verification="Verify no wildcard entries in allowedHosts",
            ))

        untrusted = [h for h in hosts if h not in TRUSTED_HOSTS and h != "*"]
        if len(untrusted) > 3:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=CATEGORY,
                title="Many external hosts allowed",
                description=f"{len(untrusted)} non-default hosts in allowlist: {', '.join(untrusted[:5])}",
                risk="Broad network access increases the attack surface for data exfiltration.",
                fix="Review and minimize the allowedHosts list to only required services",
                verification="Audit each allowed host and remove unnecessary entries",
            ))

    # Check enableAllProjectMcpServers
    if _get_setting(config, "enableAllProjectMcpServers") is True:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="All project MCP servers auto-enabled",
            description="enableAllProjectMcpServers is true. MCP servers defined in cloned repos will auto-execute.",
            risk="Malicious .mcp.json in any cloned repository can execute commands before user sees trust dialog.",
            fix='Set "enableAllProjectMcpServers": false in user settings',
            verification="Verify enableAllProjectMcpServers is false or absent in all settings layers",
        ))

    # Check enableWeakerNetworkIsolation
    if _get_sandbox_network_setting(config, "enableWeakerNetworkIsolation") is True:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title="Weaker network isolation enabled",
            description="enableWeakerNetworkIsolation is true, reducing network sandboxing effectiveness.",
            risk="Network restrictions may be bypassable, allowing unauthorized outbound connections.",
            fix='Set "enableWeakerNetworkIsolation": false in sandbox.network',
            verification="Verify enableWeakerNetworkIsolation is false or absent",
        ))

    # MCP server analysis
    mcp = config.get("mcp_servers", {})
    if not mcp:
        findings.append(Finding(
            severity=Severity.INFO,
            category=CATEGORY,
            title="No MCP servers configured",
            description="No MCP servers found in configuration.",
            risk="No additional risk, but MCP servers extend Claude's capabilities.",
            fix="No action needed unless MCP servers are expected",
            verification="N/A",
        ))
    else:
        for name, server in mcp.items():
            args = server.get("args", [])
            for arg in args:
                if "@" in arg and not _is_pinned_version(arg):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=CATEGORY,
                        title=f"Unpinned MCP package: {name}",
                        description=f'MCP server "{name}" uses unpinned package: {arg}',
                        risk="Unpinned packages can be supply-chain attacked via malicious updates.",
                        fix=f'Pin to a specific version: {arg.rsplit("@", 1)[0]}@<specific-version>',
                        verification=f'Verify "{name}" MCP server uses a pinned version',
                    ))

    # Check MCP servers in project config (supply chain risk)
    project_settings = config["settings"].get("project", {})
    project_mcp_path = config.get("project_dir", "")
    # We check if there are project-level MCP servers via the raw config
    # The mcp_servers dict merges user+project, but we flag if project defines any
    project_mcp_file = config.get("_project_mcp_servers", {})
    if project_mcp_file:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=CATEGORY,
            title="MCP servers in project config",
            description=f"Project .mcp.json defines {len(project_mcp_file)} MCP server(s). These should be explicitly reviewed.",
            risk="Project-defined MCP servers are a supply chain vector in shared repositories.",
            fix="Review each MCP server in .mcp.json and verify it is trusted and necessary",
            verification="Manually audit all servers in project .mcp.json",
        ))

    return findings
