from claude_sec.analyzers.filesystem import analyze_filesystem
from claude_sec.analyzers.network import analyze_network
from claude_sec.analyzers.hooks import analyze_hooks
from claude_sec.analyzers.git import analyze_git
from claude_sec.analyzers.permissions import analyze_permissions
from claude_sec.models import Finding


def run_all_analyzers(config: dict) -> dict[str, list[Finding]]:
    """Run all analyzers and return findings grouped by category."""
    return {
        "filesystem": analyze_filesystem(config),
        "network": analyze_network(config),
        "hooks": analyze_hooks(config),
        "git": analyze_git(config),
        "permissions": analyze_permissions(config),
    }
