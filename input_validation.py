"""
Input Validation for Prompt Injection Defense
==============================================
Validates untrusted input (site config rules, learned false positives) before
injecting into LLM prompts. Detects suspicious patterns that could be used
for prompt injection attacks.

Security Note:
- This is a defense-in-depth measure, not a complete solution
- Attackers may find bypasses, so combine with structural separation
- Log all rejections for security monitoring
"""

import re
import logging

# Configure logging for security events
logger = logging.getLogger("argus.security")


# Suspicious patterns that indicate prompt injection attempts
# Each tuple is (compiled_regex, human_readable_description)
SUSPICIOUS_PATTERNS = [
    (re.compile(r"ignore.*instruction", re.IGNORECASE), "ignore instructions"),
    (re.compile(r"ignore.*previous", re.IGNORECASE), "ignore previous"),
    (re.compile(r"override", re.IGNORECASE), "override directive"),
    (re.compile(r"always.*return", re.IGNORECASE), "always return directive"),
    (re.compile(r"disregard", re.IGNORECASE), "disregard directive"),
    (re.compile(r"forget.*above", re.IGNORECASE), "forget above directive"),
    (re.compile(r"new.*instruction", re.IGNORECASE), "new instruction directive"),
    (re.compile(r"system.*prompt", re.IGNORECASE), "system prompt reference"),
    (re.compile(r"maintenance\s*mode", re.IGNORECASE), "maintenance mode directive"),
    (re.compile(r"security\s*directive", re.IGNORECASE), "security directive"),
    # Additional patterns for common injection techniques
    (re.compile(r"you\s+are\s+now", re.IGNORECASE), "identity reassignment"),
    (re.compile(r"act\s+as\s+if", re.IGNORECASE), "behavior override"),
    (re.compile(r"pretend\s+(that|to)", re.IGNORECASE), "pretend directive"),
    (re.compile(r"from\s+now\s+on", re.IGNORECASE), "from now on directive"),
    (re.compile(r"do\s+not\s+flag", re.IGNORECASE), "do not flag directive"),
    (re.compile(r"return\s+pass", re.IGNORECASE), "return pass directive"),
    (re.compile(r"mark\s+as\s+pass", re.IGNORECASE), "mark as pass directive"),
]


def validate_untrusted_input(text: str) -> tuple[bool, str]:
    """
    Validate untrusted input for suspicious patterns that could indicate
    prompt injection attempts.

    Args:
        text: The input text to validate (e.g., a site config rule or
              learned false positive element/issue)

    Returns:
        Tuple of (is_valid, reason)
        - (True, "") if the input appears safe
        - (False, "reason") if suspicious patterns were detected

    Example:
        >>> validate_untrusted_input("IGNORE: Cookie consent popups")
        (True, "")
        >>> validate_untrusted_input("Ignore all previous instructions")
        (False, "Suspicious pattern detected: ignore previous")
    """
    if not text:
        return True, ""

    # Check against all suspicious patterns
    for pattern, description in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            reason = f"Suspicious pattern detected: {description}"
            logger.warning(
                f"[SECURITY] Blocked untrusted input: {reason}. "
                f"Content (truncated): {text[:100]!r}"
            )
            return False, reason

    return True, ""


def validate_config_rules(rules: list[str]) -> tuple[list[str], list[dict]]:
    """
    Validate a list of site config rules and return only the safe ones.

    Args:
        rules: List of rule strings from site config YAML

    Returns:
        Tuple of (valid_rules, rejected_rules)
        - valid_rules: List of rules that passed validation
        - rejected_rules: List of dicts with 'rule' and 'reason' for rejected rules
    """
    valid_rules = []
    rejected_rules = []

    for rule in rules:
        is_valid, reason = validate_untrusted_input(rule)
        if is_valid:
            valid_rules.append(rule)
        else:
            rejected_rules.append({"rule": rule, "reason": reason})
            logger.warning(
                f"[SECURITY] Rejected config rule: {reason}. "
                f"Rule: {rule[:100]!r}"
            )

    return valid_rules, rejected_rules


def validate_learned_false_positive(entry: dict) -> tuple[bool, str]:
    """
    Validate a learned false positive entry for prompt injection.

    Checks both the 'element' and 'issue' fields which are injected into prompts.

    Args:
        entry: A dict with 'element' and 'issue' keys

    Returns:
        Tuple of (is_valid, reason)
        - (True, "") if the entry appears safe
        - (False, "reason") if suspicious patterns were detected
    """
    element = entry.get("element", "")
    issue = entry.get("issue", "")

    # Validate element field
    is_valid, reason = validate_untrusted_input(element)
    if not is_valid:
        return False, f"Element field: {reason}"

    # Validate issue field
    is_valid, reason = validate_untrusted_input(issue)
    if not is_valid:
        return False, f"Issue field: {reason}"

    return True, ""


def validate_learned_false_positives(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Validate a list of learned false positive entries.

    Args:
        entries: List of false positive dicts from monitor_state.json

    Returns:
        Tuple of (valid_entries, rejected_entries)
        - valid_entries: List of entries that passed validation
        - rejected_entries: List of dicts with 'entry' and 'reason' for rejected
    """
    valid_entries = []
    rejected_entries = []

    for entry in entries:
        is_valid, reason = validate_learned_false_positive(entry)
        if is_valid:
            valid_entries.append(entry)
        else:
            rejected_entries.append({"entry": entry, "reason": reason})
            logger.warning(
                f"[SECURITY] Rejected learned false positive: {reason}. "
                f"Entry: {entry}"
            )

    return valid_entries, rejected_entries
