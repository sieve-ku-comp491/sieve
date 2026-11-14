"""Matching repeated scans by fingerprint, and the rules for hiding a finding
(docs/finding-format.md, "When a finding is hidden"; requirement F3, test 3).

Each test scans a repository URL of its own, so the scans of other tests in the same database
can't match. The first test loads the Semgrep fixture of PyGoat (tests/adapter_fixture) twice;
the others store findings with made-up fingerprints and context hashes.
"""

import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.types.json import Jsonb

from app.adapters import AdapterResult, Finding, Location
from app.runner.manifest import PluginManifest
from app.runner.runner import RunStatus
from app.store import PostgresRunStore, load_sarif
from app.store.queries import FindingFilter, FindingsReader

FIXTURE = Path(__file__).parent / "adapter_fixture"
MANIFEST = Path(__file__).resolve().parents[2] / "plugins" / "semgrep" / "plugin.toml"
COMMIT = "2aa4cc14f251e4a780e94e200aed6b36a5b15c21"
OTHER_COMMIT = "a" * 40
LAB = "dockerized_labs/sql_injection_lab/app.py"
V4_KEYS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]


def new_repo() -> str:
    return f"https://example.test/{uuid.uuid4().hex}"


def test_scanning_the_same_commit_twice_adds_nothing_to_the_queue(database, tmp_path):
    """F3, test 3, on the 9 findings of the fixture. Every finding of the first scan is
    reviewed, so every finding of the second is matched to it and hidden with its review."""
    repo = new_repo()

    def load():
        return load_sarif(
            database,
            tmp_path / uuid.uuid4().hex,
            MANIFEST,
            FIXTURE / "semgrep-pygoat.sarif",
            FIXTURE / "pygoat",
            repo,
            COMMIT,
        )

    first = load()
    with psycopg.connect(database) as conn:
        earlier = conn.execute(
            "SELECT id, fingerprint FROM findings WHERE scan_id = %s ORDER BY fingerprint",
            (first.scan_id,),
        ).fetchall()
        reviews = {
            fingerprint: review(conn, finding_id, "approve" if n % 2 else "reject")
            for n, (finding_id, fingerprint) in enumerate(earlier)
        }

    second = load()

    assert (first.findings, second.findings) == (9, 9)
    with psycopg.connect(database) as conn:
        rows = conn.execute(
            "SELECT f.fingerprint, f.matched_finding_id, f.carried_review_id, f.hidden, s.state"
            " FROM findings f JOIN finding_states s ON s.finding_id = f.id"
            " WHERE f.scan_id = %s ORDER BY f.fingerprint",
            (second.scan_id,),
        ).fetchall()
    assert [row[0] for row in rows] == [fingerprint for _, fingerprint in earlier]
    for (fingerprint, matched, carried, hidden, state), (earlier_id, _), n in zip(
        rows, earlier, range(9), strict=True
    ):
        assert (matched, carried, hidden) == (earlier_id, reviews[fingerprint], True)
        assert state == ("approved" if n % 2 else "rejected")

    reader = FindingsReader(database)
    assert reader.list_findings(second.scan_id, FindingFilter(), 100, 0) == (0, [])
    scan = reader.get_scan(second.scan_id)
    assert set(scan["state_counts"].values()) == {0} and scan["hidden_count"] == 9


@pytest.fixture
def store(database):
    return PostgresRunStore(database)


def scan(store, repo, findings, commit=COMMIT, tool="semgrep", rules_version="r1") -> list[str]:
    """Stores a scan of repo with one run of tool, and one finding for each (fingerprint,
    fields) pair. Returns the finding IDs."""
    plugin = PluginManifest(tool, "image", ("python",), tool, "1.0", rules_version)
    scan_id = store.create_scan(repo, commit_sha=commit)
    run = store.create_run(scan_id, plugin)
    run.status = RunStatus.SUCCEEDED
    result = AdapterResult(
        [
            Finding(
                scan_id=scan_id,
                run_id=run.run_id,
                tool=tool,
                tool_version="1.0",
                rule_id="rule",
                message="m",
                tool_severity="warning",
                location=Location(LAB, 57, 57),
                raw={},
                **({"fingerprint": fp, "context_hash": "c1:same"} | fields),
            )
            for fp, fields in findings
        ]
    )
    return store.save_findings(run, result)


def review(conn, finding_id, decision="reject") -> uuid.UUID:
    return conn.execute(
        "INSERT INTO reviews (finding_id, decision, reviewer) VALUES (%s, %s, 'Ali') RETURNING id",
        (finding_id, decision),
    ).fetchone()[0]


def reviewed(database, finding_id, decision="reject") -> uuid.UUID:
    with psycopg.connect(database) as conn:
        return review(conn, finding_id, decision)


def match(database, finding_id) -> tuple:
    with psycopg.connect(database) as conn:
        row = conn.execute(
            "SELECT matched_finding_id, carried_review_id, hidden FROM findings WHERE id = %s",
            (finding_id,),
        ).fetchone()
    matched, carried, hidden = row
    return (matched and str(matched), carried and str(carried), hidden)


def test_without_a_review_the_finding_is_matched_and_shown(database, store):
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {})])
    (new,) = scan(store, repo, [("v1:a", {})])
    assert match(database, new) == (old, None, False)

    # The values are fixed at import: a later review of the earlier finding doesn't hide it.
    reviewed(database, old)
    assert match(database, new) == (old, None, False)


def test_a_new_fingerprint_matches_nothing(database, store):
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {})])
    reviewed(database, old)
    (new,) = scan(store, repo, [("v1:b", {})])
    assert match(database, new) == (None, None, False)


def test_scans_of_other_repositories_are_not_matched(database, store):
    (old,) = scan(store, new_repo(), [("v1:a", {})])
    reviewed(database, old)
    (new,) = scan(store, new_repo(), [("v1:a", {})])
    assert match(database, new) == (None, None, False)


def test_a_changed_context_shows_the_earlier_review_as_a_suggestion(database, store):
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {})])
    review_id = reviewed(database, old)
    (new,) = scan(store, repo, [("v1:a", {"context_hash": "c1:changed"})])
    assert match(database, new) == (old, str(review_id), False)


def test_an_empty_context_hash_never_hides(database, store):
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {"context_hash": ""})])
    review_id = reviewed(database, old)
    (new,) = scan(store, repo, [("v1:a", {"context_hash": ""})])
    assert match(database, new) == (old, str(review_id), False)


def test_gitleaks_findings_are_never_hidden(database, store):
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {})], tool="gitleaks")
    review_id = reviewed(database, old)
    (new,) = scan(store, repo, [("v1:a", {})], tool="gitleaks")
    assert match(database, new) == (old, str(review_id), False)


@pytest.mark.parametrize("ambiguous", ["earlier", "new", "both"])
@pytest.mark.parametrize(
    ("commit", "rules_version", "hidden"),
    [(OTHER_COMMIT, "r1", False), (COMMIT, "r1", True), (COMMIT, "r2", False)],
)
def test_an_ambiguous_finding_is_hidden_only_in_a_scan_of_the_same_commit(
    database, store, ambiguous, commit, rules_version, hidden
):
    """Two scans of the same commit with the same rules give exact occurrence numbers. With
    other rules, the same commit can give other findings and so other occurrence numbers."""
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {"fingerprint_ambiguous": ambiguous != "new"})])
    review_id = reviewed(database, old)
    (new,) = scan(
        store,
        repo,
        [("v1:a", {"fingerprint_ambiguous": ambiguous != "earlier"})],
        commit=commit,
        rules_version=rules_version,
    )
    assert match(database, new) == (old, str(review_id), hidden)


def test_a_review_reaches_the_third_scan_through_a_hidden_second(database, store):
    repo = new_repo()
    (first,) = scan(store, repo, [("v1:a", {})])
    review_id = reviewed(database, first, "approve")
    (second,) = scan(store, repo, [("v1:a", {})], commit=OTHER_COMMIT)
    (third,) = scan(store, repo, [("v1:a", {})])
    assert match(database, second) == (first, str(review_id), True)
    assert match(database, third) == (second, str(review_id), True)


def test_the_latest_review_of_any_earlier_finding_counts(database, store):
    """The first finding was rejected. The second, with other code around it, was shown again
    and approved. The third has the first one's code around it, but the latest review is the
    approval of the second, whose context differs, so it is only a suggestion."""
    repo = new_repo()
    (first,) = scan(store, repo, [("v1:a", {})])
    reviewed(database, first, "reject")
    (second,) = scan(store, repo, [("v1:a", {"context_hash": "c1:other"})])
    approval = reviewed(database, second, "approve")
    (third,) = scan(store, repo, [("v1:a", {})])
    assert match(database, third) == (second, str(approval), False)


def test_an_edit_after_the_review_makes_it_a_suggestion(database, store):
    """The reviewer rejected the finding, then edited its verdict without deciding again, so
    the rejection no longer stands for it."""
    repo = new_repo()
    (old,) = scan(store, repo, [("v1:a", {})])
    review_id = reviewed(database, old, "reject")
    with psycopg.connect(database) as conn:
        scan_id = conn.execute("SELECT scan_id FROM findings WHERE id = %s", (old,)).fetchone()[0]
        run_id = conn.execute(
            "INSERT INTO triage_runs (scan_id, cheap_model, strong_model, budget_usd)"
            " VALUES (%s, 'cheap', 'strong', 1) RETURNING id",
            (scan_id,),
        ).fetchone()[0]
        verdict_id = conn.execute(
            "INSERT INTO verdicts (triage_run_id, finding_id, verdict, reasoning, cited_lines,"
            " injection_suspected, model_version, cvss_v4_vector, cvss_v4_score, cvss_v4_level,"
            " cvss_v4_justifications) VALUES (%s, %s, 'false_positive', 'r', '[{}]', false, 'm',"
            " 'CVSS:4.0/AV:N', 1.0, 'low', %s) RETURNING id",
            (run_id, old, Jsonb(dict.fromkeys(V4_KEYS, "x"))),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO finding_edits (finding_id, verdict_id, editor, verdict)"
            " VALUES (%s, %s, 'Ali', 'true_positive')",
            (old, verdict_id),
        )
    (new,) = scan(store, repo, [("v1:a", {})])
    assert match(database, new) == (old, str(review_id), False)
