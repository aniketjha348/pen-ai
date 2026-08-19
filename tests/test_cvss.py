"""Tests for CVSS v3.1 scoring."""

import pytest

from reporting.cvss import cvss_score, severity_rating, vector_from_finding


def test_cvss_score_base_case():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    score = cvss_score(vector)
    assert score == pytest.approx(6.5, abs=0.1)
    assert severity_rating(score) == "MEDIUM"


def test_cvss_score_critical():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score = cvss_score(vector)
    assert score >= 9.0
    assert severity_rating(score) == "CRITICAL"


def test_severity_rating_boundaries():
    assert severity_rating(0.0) == "NONE"
    assert severity_rating(0.1) == "LOW"
    assert severity_rating(3.9) == "LOW"
    assert severity_rating(4.0) == "MEDIUM"
    assert severity_rating(6.9) == "MEDIUM"
    assert severity_rating(7.0) == "HIGH"
    assert severity_rating(8.9) == "HIGH"
    assert severity_rating(9.0) == "CRITICAL"
    assert severity_rating(10.0) == "CRITICAL"


def test_vector_from_finding_defaults():
    vector = vector_from_finding({"severity": "high", "access": "remote"})
    assert vector.startswith("CVSS:3.1/")
    assert "PR:N" in vector
    assert "AV:N" in vector


def test_vector_from_finding_unknown_severity():
    vector = vector_from_finding({})
    assert vector.startswith("CVSS:3.1/")


def test_invalid_vector_raises():
    with pytest.raises(ValueError):
        cvss_score("not a vector")