"""Core detection engine — 8 attack classes, stdlib only.

Threat levels:
- NONE  -> allow silently
- LOW   -> allow with warning
- HIGH  -> block immediately (encoding_attack, command_injection)
"""

import re
from dataclasses import dataclass, field
from typing import Any

PATTERNS: dict[str, re.Pattern[str]] = {
    "system_override": re.compile(
        r"ignore previous|disregard instructions|you are now|new instructions:",
        re.IGNORECASE,
    ),
    "jailbreak": re.compile(
        r"DAN mode|jailbreak|bypass safety|pretend you",
        re.IGNORECASE,
    ),
    "encoding_attack": re.compile(
        r"\x00|[​‌‍﻿]",
    ),
    "data_exfil": re.compile(
        r"send to http|curl |wget |fetch\(",
        re.IGNORECASE,
    ),
    "role_injection": re.compile(
        r"```system|\[SYSTEM\]|<system>|Human:|Assistant:",
        re.IGNORECASE,
    ),
    "credential_harvest": re.compile(
        r"what is your api key|show me your token|print your password",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        # WHY: negative lookbehind (?<!\| ) excludes markdown table cells
        # like `| --flag |` while still catching `whoami`, `dangerous_cmd`.
        r"; rm |\| cat /etc|&& curl|\$\(|(?<!\| )`(?!-)[^`]+`",
    ),
    "social_engineering": re.compile(
        r"please ignore (all |the )?(previous|prior|above|earlier)"
        r" (instructions?|rules?|constraints?)|"
        r"kindly disregard|forget (all |your )?(previous |prior )?instructions|"
        r"as your (developer|admin|creator|owner|operator)|"
        r"for (debug(ging)?|test(ing)?|demo) purposes[,.]? (ignore|bypass|skip|disable)|"
        r"your new (role|persona|instructions?|directives?|task) (is|are)|"
        r"from now on (you (are|will|must|should)|ignore)|"
        r"starting (now|immediately)[,.]? you (are|will|must)|"
        r"(acting|pretend(ing)?|roleplay(ing)?) as .{0,30}(without|ignoring|bypass)",
        re.IGNORECASE,
    ),
}

# These categories block immediately on any match — direct operational risk.
HIGH_PRIORITY_CATEGORIES: frozenset[str] = frozenset({"encoding_attack", "command_injection"})

SANITIZE_PATTERN = re.compile(r"\x00|[​‌‍﻿]")


@dataclass
class ScanResult:
    hits: dict[str, int] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return not bool(self.hits)

    @property
    def is_high_priority(self) -> bool:
        return bool(HIGH_PRIORITY_CATEGORIES & set(self.hits))

    @property
    def threat_level(self) -> str:
        if not self.hits:
            return "NONE"
        if self.is_high_priority:
            return "HIGH"
        return "LOW"


def collect_strings(value: Any) -> list[str]:
    """Recursively collect all string values from an arbitrary structure."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        results: list[str] = []
        for v in value.values():
            results.extend(collect_strings(v))
        return results
    if isinstance(value, list):
        results = []
        for item in value:
            results.extend(collect_strings(item))
        return results
    return []


def sanitize(value: Any) -> Any:
    """Recursively strip null bytes and zero-width characters."""
    if isinstance(value, str):
        return SANITIZE_PATTERN.sub("", value)
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


def scan(strings: list[str]) -> dict[str, int]:
    """Return {category: match_count} for all injection hits across strings."""
    hits: dict[str, int] = {}
    for text in strings:
        for category, pattern in PATTERNS.items():
            count = len(pattern.findall(text))
            if count:
                hits[category] = hits.get(category, 0) + count
    return hits


def is_safe(text: str) -> bool:
    """Return True if text contains no injection patterns."""
    return not bool(scan([text]))
