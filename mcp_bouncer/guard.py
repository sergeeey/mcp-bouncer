"""Core detection engine — 8 attack classes, stdlib only.

Threat levels:
- NONE  -> allow silently
- LOW   -> allow with warning (data_exfil, role_injection, credential_harvest,
           social_engineering — higher context-dependence, higher FP risk)
- HIGH  -> block immediately (encoding_attack, command_injection,
           system_override, jailbreak)
"""

import re
from dataclasses import dataclass, field
from typing import Any


def _invisible_char_class() -> str:
    """Build a regex character class from invisible/control codepoint ranges.

    WHY: steganographic prompt smuggling uses soft hyphen, zero-width space/
    ZWNJ/ZWJ/LRM/RLM, bidi embedding/override, word joiner + invisible math
    operators, bidi isolates, and BOM. Built from int codepoints (not pasted
    literal invisible chars) so this file stays 100% visible ASCII — pasted
    invisible characters are unauditable by eye and fragile across editors/git.
    """
    ranges: list[tuple[int, int]] = [
        (0x00AD, 0x00AD),  # soft hyphen
        (0x200B, 0x200F),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
        (0x202A, 0x202E),  # bidi embedding/override
        (0x2060, 0x2064),  # word joiner, invisible math operators
        (0x2066, 0x2069),  # bidi isolates
        (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
    ]
    return "".join(chr(lo) if lo == hi else f"{chr(lo)}-{chr(hi)}" for lo, hi in ranges)


# WHY: Unicode tag block U+E0000-E007F hides ASCII payloads inside emoji —
# shared by encoding_attack detection AND sanitize() so both cover the same
# set (previously sanitize() only stripped 4 chars, missing this entirely).
ENCODING_PATTERN = re.compile(rf"\x00|[{_invisible_char_class()}]|[\U000e0000-\U000e007f]")
SANITIZE_PATTERN = ENCODING_PATTERN

# WHY: only flag backtick spans containing a recognized dangerous command/shell
# metachar, not ANY backtick content — the old `(?!-)[^`]+` matched `git status`,
# `npm test`, any code reference, guaranteeing false positives that get the hook
# disabled. `whoami` etc. stay flagged (test_command_injection_unsafe requires it).
_DANGEROUS_CMD = (
    r"rm|whoami|curl|wget|chmod|chown|sudo|dd|mkfs|shutdown|reboot|kill|"
    r"passwd|nc|ncat|ssh|scp|eval|exec|base64|useradd|userdel"
)

PATTERNS: dict[str, re.Pattern[str]] = {
    # WHY: "you are now" and bare "previous"/"prior" (without an instructions-like
    # noun) were dropped after HIGH-promotion review (2026-07-08) — too generic on
    # their own, verified false positives on ordinary text ("You are now connected
    # to the server.", "the parser would forget previous state on reload."). See
    # jailbreak's "pretend you" removal for the same reasoning.
    "system_override": re.compile(
        r"ignore\s+(all\s+|the\s+)?(previous|prior|above|earlier)|"
        r"disregard\s+(all\s+|the\s+)?(previous|prior|above|earlier|instructions?)|"
        r"forget\s+(all\s+|everything\s+)?"
        r"(you\s+(were|have\s+been)\s+told|(previous|prior)\s+(instructions?|rules?|directives?))|"
        r"new instructions:",
        re.IGNORECASE,
    ),
    # WHY: bare "pretend you" dropped after HIGH-promotion review — matches benign
    # text like "pretend you are a helpful assistant for kids". The more specific,
    # actually-dangerous form ("pretend ... without/ignoring/bypass ...") is already
    # covered by social_engineering below.
    "jailbreak": re.compile(
        r"D\s*A\s*N\s+mode|jailbreak|bypass safety",
        re.IGNORECASE,
    ),
    "encoding_attack": ENCODING_PATTERN,
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
        rf"; rm |\| cat /etc|&& curl|\$\(|(?<!\| )`(?:{_DANGEROUS_CMD})\b[^`]*`",
        re.IGNORECASE,
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
# WHY: system_override/jailbreak promoted from LOW to HIGH (2026-07-08) — a tool
# named "injection blocker" whose own README headline example ("Ignore previous
# instructions...") wasn't blocked by its recommended hook was the core finding
# of the audit. social_engineering/role_injection/credential_harvest/data_exfil
# stay LOW: higher context-dependence, higher FP risk on legitimate text.
HIGH_PRIORITY_CATEGORIES: frozenset[str] = frozenset(
    {"encoding_attack", "command_injection", "system_override", "jailbreak"}
)


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
        # encoding_attack is checked on RAW text (presence-based detection).
        encoding_count = len(ENCODING_PATTERN.findall(text))
        if encoding_count:
            hits["encoding_attack"] = hits.get("encoding_attack", 0) + encoding_count

        # WHY: strip invisible chars before scanning other categories — otherwise
        # "ig<word-joiner>nore previous" evades system_override by splitting the
        # keyword across an invisible character the raw-text regex never sees.
        normalized = ENCODING_PATTERN.sub("", text)
        for category, pattern in PATTERNS.items():
            if category == "encoding_attack":
                continue
            count = len(pattern.findall(normalized))
            if count:
                hits[category] = hits.get(category, 0) + count
    return hits


def is_safe(text: str) -> bool:
    """Return True if text contains no injection patterns."""
    return not bool(scan([text]))
