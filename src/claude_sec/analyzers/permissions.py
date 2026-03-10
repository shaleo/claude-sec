from claude_sec.models import Finding, Severity

CATEGORY = "permissions"

# Tool permissions that are overly broad when allowed without specifiers
BROAD_TOOL_ALLOWS = [
    ("Bash", "All bash commands allowed without restriction"),
    ("Bash(*)", "All bash commands allowed via wildcard"),
    ("Read", "All file reads allowed without restriction"),
    ("Edit", "All file edits allowed without restriction"),
    ("Write", "All file writes allowed without restriction"),
]

# Credential paths that should be in deny rules
CREDENTIAL_DENY_PATHS = [
    (".env", "Environment variable files"),
    ("~/.ssh/**", "SSH keys and config"),
    ("~/.aws/**", "AWS credentials"),
    ("~/.gnupg/**", "GPG keys"),
    ("~/.config/gh/**", "GitHub CLI credentials"),
    ("~/.git-credentials", "Git stored credentials"),
]


def _collect_all_permissions(config: dict) -> dict:
    """Collect allow and deny lists across all settings layers."""
    allow = []
    deny = []
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        perms = settings.get("permissions", {})
        allow.extend(perms.get("allow", []))
        deny.extend(perms.get("deny", []))
    return {"allow": allow, "deny": deny}


def _get_setting_any_layer(config: dict, key: str) -> object | None:
    """Get a top-level setting from any layer."""
    for layer in ["user", "project", "local"]:
        settings = config["settings"].get(layer, {})
        if key in settings:
            return settings[key]
    return None


def analyze_permissions(config: dict) -> list[Finding]:
    findings = []
    perms = _collect_all_permissions(config)
    allow_list = perms["allow"]
    deny_list = perms["deny"]

    # Check bypassPermissions mode
    default_mode = _get_setting_any_layer(config, "defaultMode")
    if default_mode == "bypassPermissions":
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="Bypass permissions mode enabled",
            description="defaultMode is set to bypassPermissions, disabling ALL permission checks.",
            risk="Claude Code can execute any operation without user approval — reads, writes, bash, network.",
            fix='Remove "defaultMode": "bypassPermissions" or set to "default"',
            verification="Verify defaultMode is not bypassPermissions in any settings layer",
        ))

    # Check ANTHROPIC_BASE_URL override in project config (CVE-2026-21852)
    project_settings = config["settings"].get("project", {})
    project_env = project_settings.get("env", {})
    if "ANTHROPIC_BASE_URL" in project_env:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="ANTHROPIC_BASE_URL override in project config",
            description=f"Project settings override ANTHROPIC_BASE_URL to: {project_env['ANTHROPIC_BASE_URL']}. "
                        "Per CVE-2026-21852, this can exfiltrate API keys to attacker-controlled endpoints.",
            risk="API keys transmitted to a malicious endpoint before trust dialog is shown.",
            fix="Remove ANTHROPIC_BASE_URL from .claude/settings.json env section. "
                "Set it in user settings or environment only if needed.",
            verification="Verify .claude/settings.json does not contain ANTHROPIC_BASE_URL in env",
        ))

    # Check for overly broad tool permissions
    for tool_pattern, desc in BROAD_TOOL_ALLOWS:
        if tool_pattern in allow_list:
            findings.append(Finding(
                severity=Severity.HIGH,
                category=CATEGORY,
                title=f"Overly broad permission: {tool_pattern}",
                description=f'"{tool_pattern}" in allow list. {desc}.',
                risk="Broad permissions eliminate safeguards against unintended or malicious operations.",
                fix=f'Replace "{tool_pattern}" with specific allowed patterns (e.g., "Bash(git status)")',
                verification=f'Verify "{tool_pattern}" is not in any permissions.allow list',
            ))

    # Check credential path deny rules
    deny_set = set(deny_list)
    missing_denies = []
    for path, desc in CREDENTIAL_DENY_PATHS:
        # Check for both Read and Bash deny patterns
        read_denied = f"Read({path})" in deny_set or any(
            path in d for d in deny_set if d.startswith("Read(")
        )
        if not read_denied:
            missing_denies.append(f"{path} ({desc})")

    if missing_denies:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title="Credential files not denied",
            description=f"Missing Read deny rules for: {', '.join(missing_denies[:5])}",
            risk="Credential files can be read via the Read tool, potentially exposing secrets.",
            fix='Add Read deny rules: "permissions": {"deny": ["Read(.env)", "Read(~/.ssh/**)", ...]}',
            verification="Verify credential paths are in permissions.deny",
        ))

    # Check read/write deny mismatch
    read_denies = [d for d in deny_list if d.startswith("Read(")]
    edit_denies = [d for d in deny_list if d.startswith("Edit(")]
    write_denies = [d for d in deny_list if d.startswith("Write(")]

    read_paths = {d[5:-1] for d in read_denies}  # extract path from Read(path)
    edit_paths = {d[5:-1] for d in edit_denies}
    write_paths = {d[6:-1] for d in write_denies}

    unmatched = read_paths - edit_paths - write_paths
    if unmatched:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=CATEGORY,
            title="Read/write deny mismatch",
            description=f"Read denied but Edit/Write not denied for: {', '.join(sorted(unmatched)[:5])}. "
                        "Denying Read does NOT deny Write/Edit (must be set separately).",
            risk="Files protected from reading can still be overwritten or edited.",
            fix="Add matching Edit/Write deny rules for all Read-denied paths",
            verification="Verify each Read deny has a corresponding Edit deny",
        ))

    # Check curl/wget not denied
    curl_denied = any("curl" in d for d in deny_list)
    wget_denied = any("wget" in d for d in deny_list)
    if not curl_denied or not wget_denied:
        missing = []
        if not curl_denied:
            missing.append("curl")
        if not wget_denied:
            missing.append("wget")
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category=CATEGORY,
            title=f"Network tools not denied: {', '.join(missing)}",
            description=f"{', '.join(missing)} not in deny list. These can bypass network sandbox restrictions.",
            risk="Data exfiltration or remote code download via command-line network tools.",
            fix=f'Add to permissions.deny: {[f"Bash({t} *)" for t in missing]}',
            verification=f"Verify {', '.join(missing)} commands are in deny list",
        ))

    return findings
