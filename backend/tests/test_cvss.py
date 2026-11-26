"""CVSS v4.0 scores. The expected scores come from the reference calculator code,
github.com/RedHatProductSecurity/cvss-v4-calculator at b0930b7, which also agreed with
app.cvss on 3,000 random base vectors."""

import pytest

from app.cvss import VectorError, level, score_v4


@pytest.mark.parametrize(
    ("vector", "score", "level_"),
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "critical"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0, "critical"),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.8, "medium"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.3, "medium"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1, "high"),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 1.0, "low"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0, "none"),
    ],
)
def test_scores_match_the_calculator(vector, score, level_):
    severity = score_v4(vector)
    assert (severity.vector, severity.score, severity.level) == (vector, score, level_)


@pytest.mark.parametrize(
    "vector",
    [
        "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:X",
        "CVSS:4.0/",
    ],
)
def test_anything_but_the_11_base_metrics_is_refused(vector):
    with pytest.raises(VectorError):
        score_v4(vector)


@pytest.mark.parametrize(
    ("score", "level_"),
    [
        (0.0, "none"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_levels_follow_the_specification(score, level_):
    assert level(score) == level_
