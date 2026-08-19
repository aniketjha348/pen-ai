"""CVSS v3.1 base score calculation, pure stdlib implementation.

Implements the published FIRST.org CVSS v3.1 specification: vector parsing,
impact/exploitability sub-scores, scope handling and the round-up rule.
"""

import math
import re

_VECTOR_PATTERN = re.compile(r"^CVSS:3\.[01]/(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|C:[NLH]|I:[NLH]|A:[NLH])")

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_UNCHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_PRIVILEGES_CHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.00}

_UNCHANGED_WEIGHT = 6.42
_CHANGED_WEIGHT = 7.52
_CHANGED_MINUS = 0.029
_CHANGED_EXP = 3.25
_CHANGED_EXP_ARG = 0.02
_CHANGED_EXP_POWER = 15
_EXPLOITABILITY_WEIGHT = 8.22
_CHANGED_SCOPE_MULTIPLIER = 1.08


def _roundup(value: float) -> float:
    return math.ceil(value * 10) / 10


def severity_rating(score: float) -> str:
    """Map a CVSS base score to its textual severity rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def cvss_score(vector: str) -> float:
    """Calculate the CVSS v3.1 base score for a vector string."""
    if not _VECTOR_PATTERN.match(vector):
        raise ValueError(f"invalid CVSS v3.1 vector: {vector!r}")
    metrics = dict(part.split(":") for part in vector.split("/")[1:])

    av = _ATTACK_VECTOR[metrics["AV"]]
    ac = _ATTACK_COMPLEXITY[metrics["AC"]]
    scope_changed = metrics["S"] == "C"
    pr = (_PRIVILEGES_CHANGED if scope_changed else _PRIVILEGES_UNCHANGED)[metrics["PR"]]
    ui = _USER_INTERACTION[metrics["UI"]]
    c = _IMPACT[metrics["C"]]
    i = _IMPACT[metrics["I"]]
    a = _IMPACT[metrics["A"]]

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = _CHANGED_WEIGHT * (iss - _CHANGED_MINUS) - _CHANGED_EXP * (iss - _CHANGED_EXP_ARG) ** _CHANGED_EXP_POWER
    else:
        impact = _UNCHANGED_WEIGHT * iss
    exploitability = _EXPLOITABILITY_WEIGHT * av * ac * pr * ui

    if scope_changed:
        base = _CHANGED_SCOPE_MULTIPLIER * min(impact + exploitability, 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup(base)


def vector_from_finding(finding: dict) -> str:
    """Build a plausible CVSS v3.1 vector from a finding's metadata."""
    severity = str(finding.get("severity", "medium")).upper()
    if severity in ("CRITICAL", "HIGH"):
        impact = "H"
        pr = "N"
    elif severity == "LOW":
        impact = "L"
        pr = "H"
    else:
        impact = "L"
        pr = "N"
    access = str(finding.get("access", "remote")).lower()
    av = "N" if access in ("remote", "network") else "A"
    return (
        f"CVSS:3.1/AV:{av}/AC:L/PR:{pr}/UI:R/S:U/"
        f"C:{impact}/I:{impact}/A:{impact}"
    )