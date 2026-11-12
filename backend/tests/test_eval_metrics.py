"""The evaluation's metrics, each on a small example whose answer was worked out by hand."""

import pytest

from app.eval.expected import Expected
from app.eval.metrics import (
    Finding,
    MetricError,
    cost_and_time,
    false_positive_check,
    level,
    merge_precision_recall,
    read_findings,
    related,
    severity_agreement,
)


def case(case_id: str, cwe: str, file: str, real: bool) -> Expected:
    return Expected("benchmark-java", case_id, cwe, file, None, None, "", "", real)


CASES = [
    case("A", "CWE-89", "a.java", True),
    case("B", "CWE-22", "b.java", True),
    case("C", "CWE-89", "c.java", False),
    case("D", "CWE-79", "d.java", False),
]
FINDINGS = [
    Finding("f1", "a.java", frozenset({"CWE-89"}), "true_positive"),
    Finding("f2", "b.java", frozenset({"CWE-23"}), "false_positive"),
    Finding("f3", "c.java", frozenset({"CWE-89"}), "false_positive"),
    Finding("f4", "d.java", frozenset({"CWE-80"}), "unsure"),
    Finding("f5", "a.java", frozenset({"CWE-79"}), "true_positive"),
]


def test_false_positive_check():
    # Raw: A and B are flagged and real (B through the related CWE-23), C and D are flagged and
    # not real. Triage drops f2 and f3, so B is missed and C is cleared. D stays, as unsure.
    result = false_positive_check(CASES, FINDINGS)
    assert result["raw"] == {
        "tp": 2,
        "fp": 2,
        "fn": 0,
        "tn": 0,
        "tpr": 1.0,
        "fpr": 1.0,
        "score": 0.0,
    }
    assert result["triaged"] == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "tpr": 0.5,
        "fpr": 0.5,
        "score": 0.0,
    }
    assert result["findings_without_case"] == 0
    assert result["false_positives_removed"] == 0.5
    assert result["true_positives_kept"] == 0.5
    assert result["by_cwe"]["CWE-89"]["raw"]["fp"] == 1
    assert result["by_cwe"]["CWE-89"]["triaged"] == {
        "tp": 1,
        "fp": 0,
        "fn": 0,
        "tn": 1,
        "tpr": 1.0,
        "fpr": 0.0,
        "score": 1.0,
    }


def test_a_finding_in_another_file_or_cwe_does_not_count():
    result = false_positive_check(
        [case("A", "CWE-89", "a.java", True)],
        [
            Finding("f", "b.java", frozenset({"CWE-89"})),
            Finding("g", "a.java", frozenset({"CWE-79"})),
        ],
    )
    assert result["raw"]["fn"] == 1
    assert result["true_positives_kept"] is None


def test_related_cwes():
    assert related("CWE-78", "CWE-77")
    assert related("CWE-22", "CWE-22")
    assert related("CWE-327", "CWE-328")
    assert not related("CWE-327", "CWE-330")
    assert not related("CWE-89", "CWE-79")


def test_each_case_once():
    with pytest.raises(MetricError):
        false_positive_check(CASES + CASES[:1], FINDINGS)


def test_read_findings(tmp_path):
    path = tmp_path / "findings.csv"
    path.write_text("finding_id,file,cwe,verdict\nf1,a.java,89;CWE-564,\nf2,b.py,CWE-022,unsure\n")
    first, second = read_findings(path)
    assert first.cwes == {"CWE-89", "CWE-564"} and first.verdict == ""
    assert second.cwes == {"CWE-22"}
    path.write_text("finding_id,file,cwe,verdict\nf1,a.java,89,maybe\n")
    with pytest.raises(MetricError, match="unknown verdict"):
        read_findings(path)


def test_merge_precision_recall():
    # Labeled pairs: ab, ac, bc, de. Merged pairs: ab, cd, ef. Only ab is right.
    labeled = {"a": "g1", "b": "g1", "c": "g1", "d": "g2", "e": "g2", "f": ""}
    predicted = {"a": "x", "b": "x", "c": "y", "d": "y", "e": "z", "f": "z"}
    assert merge_precision_recall(labeled, predicted) == {
        "findings": 6,
        "labeled_pairs": 4,
        "merged_pairs": 3,
        "correct_pairs": 1,
        "precision": 0.3333,
        "recall": 0.25,
    }


def test_no_merges_has_no_precision():
    result = merge_precision_recall({"a": "g", "b": "g"}, {"a": "", "b": ""})
    assert result["precision"] is None and result["recall"] == 0.0


def test_merges_need_the_same_findings():
    with pytest.raises(MetricError):
        merge_precision_recall({"a": "g"}, {"b": "g"})


SEVERITY = [
    {
        # PR differs: 7 of 8 metrics match, 9.8 against 8.8, critical against high.
        "case_id": "CVE-1",
        "published_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "published_score": "9.8",
        "predicted_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "predicted_score": "8.8",
    },
    {
        # VA differs: 10 of 11 metrics match, and both score 9.3, critical.
        "case_id": "CVE-2",
        "published_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "published_score": "9.3",
        "predicted_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "predicted_score": "9.3",
    },
]


def test_severity_agreement():
    assert severity_agreement(SEVERITY) == {
        "cases": 2,
        "no_prediction": 0,
        "metrics_matched": round((7 / 8 + 10 / 11) / 2, 4),
        "mean_score_error": 0.5,
        "max_score_error": 1.0,
        "level_agreement": 0.5,
    }


def test_cvss_3_0_and_3_1_share_metrics_but_not_with_4_0():
    row = dict(SEVERITY[0], published_vector=SEVERITY[0]["published_vector"].replace("3.1", "3.0"))
    assert severity_agreement([row])["cases"] == 1
    mixed = dict(SEVERITY[0], predicted_vector=SEVERITY[1]["predicted_vector"])
    with pytest.raises(MetricError, match="versions differ"):
        severity_agreement([mixed])
    short = dict(SEVERITY[0], predicted_vector="CVSS:3.1/AV:N/AC:L")
    with pytest.raises(MetricError, match="missing base metrics"):
        severity_agreement([short])


@pytest.mark.parametrize(
    "score, expected",
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
def test_level(score, expected):
    assert level(score) == expected


def test_level_out_of_range():
    with pytest.raises(MetricError):
        level(10.1)


def test_cost_and_time():
    rows = [
        {"finding_id": "f1", "cost_usd": "0.010", "seconds": "4"},
        {"finding_id": "f2", "cost_usd": "0.020", "seconds": "6"},
        {"finding_id": "f3", "cost_usd": "0.000", "seconds": "2"},
    ]
    assert cost_and_time(rows) == {
        "findings": 3,
        "total_cost_usd": "0.030",
        "mean_cost_usd": "0.010000",
        "median_cost_usd": "0.010",
        "total_seconds": 12.0,
        "mean_seconds": 4.0,
        "median_seconds": 4.0,
    }


def test_findings_in_files_that_are_no_case_are_counted():
    findings = [*FINDINGS, Finding("f6", "src/a.java", frozenset({"CWE-89"}))]
    assert false_positive_check(CASES, findings)["findings_without_case"] == 1


def test_severity_without_a_prediction_is_counted_not_scored():
    missing = dict(SEVERITY[0], case_id="CVE-3", predicted_vector="", predicted_score="")
    result = severity_agreement([*SEVERITY, missing])
    assert result["cases"] == 3 and result["no_prediction"] == 1
    assert result["level_agreement"] == 0.5
    with pytest.raises(MetricError, match="no case has a predicted vector"):
        severity_agreement([missing])


def test_cost_that_is_not_a_number():
    with pytest.raises(MetricError, match="must be numbers"):
        cost_and_time([{"finding_id": "f1", "cost_usd": "free", "seconds": "4"}])
