"""Terminal report rendering."""

from __future__ import annotations

from .checks import FAIL, PASS, SKIP, WARN

COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", SKIP: "\033[90m"}
RESET = "\033[0m"
WEIGHTS = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}


def score(results):
    """Return a score from 0 to 100 ignoring skipped checks."""
    scored = [r for r in results if r.status in WEIGHTS]
    if not scored:
        return 0
    return round(100 * sum(WEIGHTS[r.status] for r in scored) / len(scored))


def render(results, color=True):
    lines = []
    for result in results:
        tag = f"[{result.status}]"
        if color:
            tag = f"{COLORS[result.status]}{tag}{RESET}"
        lines.append(f"{tag} {result.name}: {result.message}")
        if result.fix and result.status in (WARN, FAIL):
            lines.append(f"       Fix: {result.fix}")
    lines.append("")
    lines.append(f"Security score: {score(results)}/100")
    return "\n".join(lines)
