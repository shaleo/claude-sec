from claude_sec.models import Finding, Severity

CATEGORY = "filesystem"

SENSITIVE_PATHS = [
    ("~/.ssh", "SSH keys and config"),
    ("~/.aws", "AWS credentials"),
    ("~/.gnupg", "GPG keys"),
    ("~/.config/gcloud", "Google Cloud credentials"),
    ("~/.kube", "Kubernetes config"),
    ("~/.docker", "Docker credentials"),
    ("~/.azure", "Azure credentials"),
    ("~/.npmrc", "npm auth tokens"),
    ("~/.pypirc", "PyPI credentials"),
    ("~/.gem/credentials", "RubyGems credentials"),
    ("~/.git-credentials", "Git stored credentials"),
    ("~/.config/gh", "GitHub CLI credentials"),
    ("~/Library/Keychains", "macOS Keychain"),
]

SHELL_CONFIGS = [
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.bash_profile",
]

BROAD_WRITE_PATHS = ["/", "~", "~/", "/Users", "/home", "/usr", "/etc"]

ENV_DENY_PATTERNS = [".env", ".env.*", "**/.env", "**/.env.*"]


def _get_sandbox(config: dict, key: str) -> dict | None:
    """Extract a sandbox sub-key from any settings layer."""
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        sandbox = settings.get("sandbox", {})
        if key in sandbox:
            return sandbox[key]
    return None


def _get_sandbox_setting(config: dict, key: str) -> object | None:
    """Get a top-level sandbox setting (bool/string) from any layer."""
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        sandbox = settings.get("sandbox", {})
        if key in sandbox:
            return sandbox[key]
    return None


def analyze_filesystem(config: dict) -> list[Finding]:
    findings = []
    fs = _get_sandbox(config, "filesystem")

    if fs is None:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="No filesystem sandbox configured",
            description="No sandbox filesystem rules found in any settings layer. All file operations are unrestricted.",
            risk="Claude Code can read and write any file on the system without restriction.",
            fix='Add "sandbox": {"filesystem": {"write": {"allowOnly": ["."]}}} to settings.json',
            verification="Check settings.json for sandbox.filesystem configuration",
        ))
        return findings

    write_rules = fs.get("write", {})
    read_rules = fs.get("read", {})

    # Check for overly broad write allowlist
    allow_only = write_rules.get("allowOnly", [])
    for path in allow_only:
        if path in BROAD_WRITE_PATHS:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title="Overly broad write allowlist",
                description=f'Write allowlist includes "{path}" which grants write access to a very large directory tree.',
                risk="Claude Code can modify files far beyond the project directory.",
                fix=f'Replace "{path}" with specific project paths in sandbox.filesystem.write.allowOnly',
                verification="Review write.allowOnly and ensure it only includes project-specific paths",
            ))

    # Check sensitive paths
    deny_list = write_rules.get("denyWithinAllow", [])
    deny_set = set(deny_list)
    for path, desc in SENSITIVE_PATHS:
        if path not in deny_set and f"{path}/*" not in deny_set and f"{path}/**" not in deny_set:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title=f"Sensitive path unprotected: {path}",
                description=f"{path} ({desc}) is not in the write deny list.",
                risk=f"{desc} could be read or modified by Claude Code.",
                fix=f'Add "{path}" to sandbox.filesystem.write.denyWithinAllow',
                verification=f'Verify "{path}" appears in denyWithinAllow list',
            ))

    # Check shell config protection
    for shell_path in SHELL_CONFIGS:
        if shell_path not in deny_set and f"{shell_path}/*" not in deny_set:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title=f"Shell config writable: {shell_path}",
                description=f"{shell_path} is not in the write deny list. Malicious code could be injected into shell startup.",
                risk="Backdoor commands in shell configs execute on every terminal session.",
                fix=f'Add "{shell_path}" to sandbox.filesystem.write.denyWithinAllow',
                verification=f'Verify "{shell_path}" appears in denyWithinAllow list',
            ))

    # Check .env file protection
    env_patterns_present = [p for p in ENV_DENY_PATTERNS if p in deny_set]
    if len(env_patterns_present) < len(ENV_DENY_PATTERNS):
        missing = [p for p in ENV_DENY_PATTERNS if p not in deny_set]
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title=".env files not fully denied",
            description=f"Missing .env deny patterns: {', '.join(missing)}",
            risk="Environment files containing secrets could be read or modified.",
            fix=f'Add {missing} to sandbox.filesystem.write.denyWithinAllow',
            verification="Verify all .env patterns are in denyWithinAllow",
        ))

    # Check read deny rules
    read_deny = read_rules.get("denyOnly", [])
    if not read_deny:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=CATEGORY,
            title="No read deny rules configured",
            description="No read.denyOnly rules found. Sensitive files can be read without restriction.",
            risk="Secrets in .env files or credential files could be read.",
            fix='Add "read": {"denyOnly": [".env", ".env.*", "**/.env", "**/.env.*"]} to sandbox.filesystem',
            verification="Check for read.denyOnly in sandbox filesystem config",
        ))

    # Check Docker socket exposure
    network = _get_sandbox(config, "network") or {}
    unix_sockets = network.get("allowUnixSockets", [])
    if "/var/run/docker.sock" in unix_sockets:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="Docker socket exposed",
            description="Docker socket (/var/run/docker.sock) is in allowUnixSockets. This allows full container host access.",
            risk="Docker socket access enables container escape and full host compromise.",
            fix='Remove "/var/run/docker.sock" from sandbox.network.allowUnixSockets',
            verification="Verify Docker socket is not in allowUnixSockets",
        ))

    # Check allowAllUnixSockets
    if network.get("allowAllUnixSockets") is True:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="All Unix sockets allowed",
            description="sandbox.network.allowAllUnixSockets is true. This bypasses socket-level isolation.",
            risk="Access to all Unix sockets including Docker, databases, and other local services.",
            fix='Set "allowAllUnixSockets": false in sandbox.network',
            verification="Verify allowAllUnixSockets is false or absent",
        ))

    # Check enableWeakerNestedSandbox
    if _get_sandbox_setting(config, "enableWeakerNestedSandbox") is True:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title="Weaker nested sandbox enabled",
            description="enableWeakerNestedSandbox is true, which considerably weakens security for nested processes.",
            risk="Child processes may escape sandbox restrictions.",
            fix='Set "enableWeakerNestedSandbox": false in sandbox settings',
            verification="Verify enableWeakerNestedSandbox is false or absent",
        ))

    # Check allowUnsandboxedCommands
    if _get_sandbox_setting(config, "allowUnsandboxedCommands") is True:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="Unsandboxed commands allowed",
            description="allowUnsandboxedCommands is true. Commands can bypass the sandbox entirely.",
            risk="Complete sandbox escape — any command can run without filesystem or network restrictions.",
            fix='Set "allowUnsandboxedCommands": false in sandbox settings',
            verification="Verify allowUnsandboxedCommands is false or absent",
        ))

    return findings
