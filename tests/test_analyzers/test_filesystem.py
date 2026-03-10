from claude_sec.analyzers.filesystem import analyze_filesystem
from claude_sec.models import Severity


def _config_with_sandbox(sandbox_rules, network_rules=None):
    """Build a config with specific sandbox filesystem rules."""
    sandbox = {}
    if sandbox_rules:
        sandbox["filesystem"] = sandbox_rules
    if network_rules:
        sandbox["network"] = network_rules
    return {
        "settings": {
            "user": {"sandbox": sandbox} if sandbox else {},
            "project": {},
            "local": {},
        },
        "mcp_servers": {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }


def test_no_sandbox_config(empty_config):
    findings = analyze_filesystem(empty_config)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("sandbox" in f.title.lower() or "sandbox" in f.description.lower() for f in critical)


def test_sandbox_with_broad_write_allowlist():
    config = _config_with_sandbox({
        "write": {"allowOnly": ["/"]}
    })
    findings = analyze_filesystem(config)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert any("broad" in f.title.lower() or "broad" in f.description.lower() for f in high)


def test_sensitive_paths_unprotected():
    config = _config_with_sandbox({
        "write": {"allowOnly": ["."], "denyWithinAllow": []}
    })
    findings = analyze_filesystem(config)
    # Should flag ~/.ssh, ~/.aws, etc. as unprotected
    sensitive_findings = [f for f in findings if "sensitive" in f.title.lower() or "ssh" in f.description.lower() or "aws" in f.description.lower()]
    assert len(sensitive_findings) > 0


def test_trail_of_bits_paths_checked():
    """New paths from Trail of Bits should be checked."""
    config = _config_with_sandbox({
        "write": {"allowOnly": ["."], "denyWithinAllow": []}
    })
    findings = analyze_filesystem(config)
    titles = [f.title for f in findings]
    assert any("~/.npmrc" in t for t in titles)
    assert any("~/.git-credentials" in t for t in titles)
    assert any("~/Library/Keychains" in t for t in titles)


def test_env_files_denied():
    config = _config_with_sandbox({
        "write": {"allowOnly": ["."], "denyWithinAllow": [".env", ".env.*", "**/.env", "**/.env.*"]}
    })
    findings = analyze_filesystem(config)
    env_findings = [f for f in findings if ".env" in f.title.lower()]
    assert len(env_findings) == 0


def test_env_files_not_denied():
    config = _config_with_sandbox({
        "write": {"allowOnly": ["."], "denyWithinAllow": []}
    })
    findings = analyze_filesystem(config)
    env_findings = [f for f in findings if ".env" in f.title.lower() or ".env" in f.description.lower()]
    assert any(f.severity >= Severity.HIGH for f in env_findings)


def test_read_deny_only_missing():
    config = _config_with_sandbox({
        "read": {},
        "write": {"allowOnly": ["."], "denyWithinAllow": [".env"]}
    })
    findings = analyze_filesystem(config)
    read_findings = [f for f in findings if "read" in f.title.lower() and "deny" in f.title.lower()]
    assert len(read_findings) > 0


def test_shell_config_unprotected():
    """Shell configs should be flagged when not in deny list."""
    config = _config_with_sandbox({
        "write": {"allowOnly": ["."], "denyWithinAllow": []}
    })
    findings = analyze_filesystem(config)
    shell = [f for f in findings if "shell config" in f.title.lower()]
    assert len(shell) >= 4  # ~/.bashrc, ~/.zshrc, ~/.profile, ~/.bash_profile


def test_shell_config_protected():
    """Shell configs in deny list should not be flagged."""
    config = _config_with_sandbox({
        "write": {
            "allowOnly": ["."],
            "denyWithinAllow": ["~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile"],
        }
    })
    findings = analyze_filesystem(config)
    shell = [f for f in findings if "shell config" in f.title.lower()]
    assert len(shell) == 0


def test_docker_socket_exposed():
    config = _config_with_sandbox(
        {"write": {"allowOnly": ["."], "denyWithinAllow": []}},
        network_rules={"allowUnixSockets": ["/var/run/docker.sock"]},
    )
    findings = analyze_filesystem(config)
    docker = [f for f in findings if "docker socket" in f.title.lower()]
    assert len(docker) == 1
    assert docker[0].severity == Severity.CRITICAL


def test_all_unix_sockets_allowed():
    config = _config_with_sandbox(
        {"write": {"allowOnly": ["."], "denyWithinAllow": []}},
        network_rules={"allowAllUnixSockets": True},
    )
    findings = analyze_filesystem(config)
    unix = [f for f in findings if "unix sockets" in f.title.lower()]
    assert len(unix) == 1
    assert unix[0].severity == Severity.CRITICAL


def test_weaker_nested_sandbox():
    config = {
        "settings": {
            "user": {"sandbox": {
                "filesystem": {"write": {"allowOnly": ["."], "denyWithinAllow": []}},
                "enableWeakerNestedSandbox": True,
            }},
            "project": {},
            "local": {},
        },
        "mcp_servers": {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }
    findings = analyze_filesystem(config)
    nested = [f for f in findings if "weaker nested" in f.title.lower()]
    assert len(nested) == 1
    assert nested[0].severity == Severity.HIGH


def test_unsandboxed_commands():
    config = {
        "settings": {
            "user": {"sandbox": {
                "filesystem": {"write": {"allowOnly": ["."], "denyWithinAllow": []}},
                "allowUnsandboxedCommands": True,
            }},
            "project": {},
            "local": {},
        },
        "mcp_servers": {},
        "hooks": {},
        "paths_scanned": [],
        "project_dir": "/tmp/test",
    }
    findings = analyze_filesystem(config)
    unsandboxed = [f for f in findings if "unsandboxed" in f.title.lower()]
    assert len(unsandboxed) == 1
    assert unsandboxed[0].severity == Severity.CRITICAL
