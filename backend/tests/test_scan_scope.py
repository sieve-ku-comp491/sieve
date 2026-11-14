"""The scope file and its URL rules (requirement F2, acceptance tests 2 and 3)."""

from pathlib import Path

import pytest

from app.scan import OutOfScope, ScopeError, ScopeFile, UrlError, normalize_url

ROOT = Path(__file__).resolve().parents[2]
PYGOAT = "https://github.com/adeyosemanputra/pygoat"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "scope.toml"
    path.write_text(text, encoding="utf-8")
    return path


def scope_with(tmp_path: Path, *urls: str) -> ScopeFile:
    entries = "".join(f'[[repository]]\nurl = "{url}"\nreason = "test"\n\n' for url in urls)
    return ScopeFile.load(write(tmp_path, entries))


def test_the_committed_scope_file_lists_the_three_targets_with_reasons():
    scope = ScopeFile.load(ROOT / "scope.toml")
    assert [entry.normalized_url for entry in scope.entries] == [
        PYGOAT,
        "https://github.com/WebGoat/WebGoat",
        "https://github.com/juice-shop/juice-shop",
    ]
    assert all("deliberately vulnerable application" in e.reason for e in scope.entries)


def test_the_committed_scope_file_says_public_code_only():
    text = (ROOT / "scope.toml").read_text(encoding="utf-8")
    assert "Public code only" in text


@pytest.mark.parametrize(
    "url",
    [
        f"{PYGOAT}.git",
        "https://GitHub.com/adeyosemanputra/pygoat/",
        PYGOAT,
        f"{PYGOAT}.git/",
    ],
)
def test_spellings_of_the_same_repository_match_its_entry(tmp_path, url):
    scope = scope_with(tmp_path, PYGOAT)
    assert scope.allows(url).url == PYGOAT


def test_another_repository_of_the_same_owner_is_refused_naming_it_and_the_file(tmp_path):
    scope = scope_with(tmp_path, PYGOAT)
    with pytest.raises(OutOfScope) as refused:
        scope.allows("https://github.com/adeyosemanputra/other-repo")
    message = str(refused.value)
    assert "https://github.com/adeyosemanputra/other-repo" in message
    assert str(tmp_path / "scope.toml") in message


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("https://user:token@github.com/adeyosemanputra/pygoat", "user name or password"),
        ("https://user@github.com/adeyosemanputra/pygoat", "user name or password"),
        ("http://github.com/adeyosemanputra/pygoat", "must start with https://"),
        ("ssh://git@github.com/adeyosemanputra/pygoat", "must start with https://"),
        ("git@github.com:adeyosemanputra/pygoat.git", "must start with https://"),
        ("https://github.com:443/adeyosemanputra/pygoat", "port"),
        ("https://github.com/adeyosemanputra/pygoat?ref=x", "query"),
        ("https://github.com/adeyosemanputra/pygoat#readme", "fragment"),
        ("https://github.com/adeyosemanputra/pygoat#", "fragment"),
        ("https://github.com", "path"),
        ("https://github.com/", "path"),
        ("https://github.com/adeyosemanputra/../pygoat", "path"),
        ("https://github.com//pygoat", "path"),
        ("https:///pygoat", "host"),
        (" https://github.com/adeyosemanputra/pygoat", "space"),
        ("https://github.com/adeyosemanputra\\pygoat", "backslash"),
        ("", "empty"),
    ],
)
def test_urls_that_break_the_rules_are_refused(tmp_path, url, problem):
    scope = scope_with(tmp_path, PYGOAT)
    with pytest.raises(UrlError, match=problem) as refused:
        scope.allows(url)
    assert "token" not in str(refused.value)


def test_normalizing_lowercases_only_the_host():
    assert normalize_url("https://GITHUB.com/Owner/Repo.git/") == "https://github.com/Owner/Repo"


def test_an_entry_without_a_reason_is_rejected_naming_it(tmp_path):
    path = write(
        tmp_path,
        f'[[repository]]\nurl = "{PYGOAT}"\nreason = "test"\n\n'
        '[[repository]]\nurl = "https://github.com/juice-shop/juice-shop"\n',
    )
    with pytest.raises(ScopeError) as rejected:
        ScopeFile.load(path)
    message = str(rejected.value)
    assert "entry 2 (https://github.com/juice-shop/juice-shop)" in message
    assert "no reason" in message
    assert str(path) in message


def test_an_empty_reason_counts_as_none(tmp_path):
    path = write(tmp_path, f'[[repository]]\nurl = "{PYGOAT}"\nreason = "  "\n')
    with pytest.raises(ScopeError, match="entry 1 .*no reason"):
        ScopeFile.load(path)


@pytest.mark.parametrize(
    ("url", "shown", "problem"),
    [
        ("http://github.com/a/b", "http://github.com/a/b", "https://"),
        ("https://me:secret@github.com/a/b", "https://github.com/a/b", "password"),
        ("https://github.com:8443/a/b", "https://github.com:8443/a/b", "port"),
        ("https://github.com/a/b?x=1", "https://github.com/a/b?x=1", "query"),
    ],
)
def test_an_entry_whose_url_breaks_the_rules_is_rejected_naming_it(tmp_path, url, shown, problem):
    path = write(tmp_path, f'[[repository]]\nurl = "{url}"\nreason = "test"\n')
    with pytest.raises(ScopeError) as rejected:
        ScopeFile.load(path)
    message = str(rejected.value)
    assert f"entry 1 ({shown})" in message
    assert problem in message
    assert "secret" not in message


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ('[[repository]]\nreason = "test"\n', "entry 1: no url"),
        (f'[[repository]]\nurl = "{PYGOAT}"\nreason = "test"\nbranch = "main"\n', "unknown keys"),
        (f'repository = "{PYGOAT}"\n', r"\[\[repository\]\]"),
        ("[[repository]\n", "not valid TOML"),
        (
            f'[[repository]]\nurl = "{PYGOAT}"\nreason = "a"\n\n'
            f'[[repository]]\nurl = "{PYGOAT}.git"\nreason = "b"\n',
            "entry 2 .*same repository as entry 1",
        ),
    ],
)
def test_other_broken_scope_files_are_rejected(tmp_path, text, problem):
    with pytest.raises(ScopeError, match=problem):
        ScopeFile.load(write(tmp_path, text))


def test_a_missing_scope_file_is_an_error_naming_it(tmp_path):
    with pytest.raises(ScopeError, match="can't read the scope file"):
        ScopeFile.load(tmp_path / "missing.toml")


def test_an_empty_scope_file_allows_nothing(tmp_path):
    with pytest.raises(OutOfScope):
        ScopeFile.load(write(tmp_path, "")).allows(PYGOAT)
