from claude_sec.models import Finding, Severity

CATEGORY = "hooks"

KEY_EVENTS = ["PreToolUse", "PostToolUse", "SessionStart"]

FAIL_OPEN_PATTERNS = [
    "|| exit 0",
    "|| true",
    "except: pass",
    "except Exception: pass",
    "|| :",
    "catch {}",
    "catch (e) {}",
]


def analyze_hooks(config: dict) -> list[Finding]:
    findings = []
    hooks = config.get("hooks", {})

    if not hooks:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=CATEGORY,
            title="No hooks configured",
            description="No hooks found in any settings layer. Tool use is completely unmonitored.",
            risk="Claude Code can execute any allowed tool with no validation or logging.",
            fix='Add hooks to settings.json under "hooks": {"PreToolUse": [...]}',
            verification="Check settings.json for hooks configuration",
        ))
        return findings

    # Check key event coverage
    for event in KEY_EVENTS:
        if event not in hooks:
            severity = Severity.HIGH if event == "PreToolUse" else Severity.MEDIUM
            findings.append(Finding(
                severity=severity,
                category=CATEGORY,
                title=f"Missing {event} hook",
                description=f"No {event} hook configured. This event is not being monitored.",
                risk=f"{'Tool use is not validated before execution' if event == 'PreToolUse' else f'{event} events are not monitored'}.",
                fix=f'Add a {event} hook: "hooks": {{"{event}": [{{"matcher": "*", "hooks": [{{"type": "command", "command": "your-script.sh"}}]}}]}}',
                verification=f"Verify {event} appears in hooks configuration",
            ))

    # Check for fail-open patterns in hook commands
    for event, handlers in hooks.items():
        if not isinstance(handlers, list):
            continue
        for handler in handlers:
            hook_list = handler.get("hooks", [])
            for hook in hook_list:
                cmd = hook.get("command", "")
                for pattern in FAIL_OPEN_PATTERNS:
                    if pattern in cmd:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category=CATEGORY,
                            title=f"Fail-open pattern in {event} hook",
                            description=f'Hook command contains "{pattern}" which silences failures.',
                            risk="If the validation script fails, the tool use will still proceed.",
                            fix=f"Remove the fail-open pattern from the hook command. Let failures propagate.",
                            verification=f"Review {event} hook commands for error suppression patterns",
                        ))

    # Check for hooks defined in project settings (supply chain risk per CVE-2025-59536)
    project_settings = config["settings"].get("project", {})
    project_hooks = project_settings.get("hooks", {})
    if project_hooks:
        findings.append(Finding(
            severity=Severity.HIGH,
            category=CATEGORY,
            title="Hooks in project settings (supply chain risk)",
            description=f"Project .claude/settings.json defines hooks for: {', '.join(project_hooks.keys())}. "
                        "Per CVE-2025-59536, malicious hooks in cloned repos can execute arbitrary commands.",
            risk="Repository-controlled hooks can run arbitrary shell commands on SessionStart or tool use.",
            fix="Move hooks to user settings (~/.claude/settings.json) or managed settings. "
                "Remove hooks from .claude/settings.json in the repo.",
            verification="Verify .claude/settings.json in the repo does not contain hooks",
        ))

    return findings
