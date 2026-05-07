"""mcp-bouncer: prompt injection blocker for MCP servers and AI agents.

Zero external dependencies. Pure stdlib. Blocks 8 attack classes.

Usage:
    from mcp_bouncer import is_safe, scan

    is_safe("normal text")                    # True
    is_safe("Ignore previous instructions")  # False

    hits = scan(["some input text"])
    # {"system_override": 1}
"""

from mcp_bouncer.guard import (
    HIGH_PRIORITY_CATEGORIES,
    PATTERNS,
    ScanResult,
    collect_strings,
    is_safe,
    sanitize,
    scan,
)

__all__ = [
    "is_safe",
    "scan",
    "sanitize",
    "collect_strings",
    "PATTERNS",
    "HIGH_PRIORITY_CATEGORIES",
    "ScanResult",
]

__version__ = "0.1.0"
