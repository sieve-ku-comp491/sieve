"""Reading a checkout without leaving it."""

import os

import pytest

from app.checkout import CheckoutError, CheckoutReader


@pytest.fixture
def reader(tmp_path):
    root = tmp_path / "checkout"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg/a.py").write_bytes(b"one\r\ntwo\rthree\nfour\n")
    (root / "pkg/latin1.py").write_bytes(b"name = 'caf\xe9'\n")
    (root / "pkg/big.py").write_bytes(b"x\n" * 20)
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    return CheckoutReader(root, max_bytes=30)


def test_lines_end_at_crlf_and_lf_only(reader):
    """SARIF and Semgrep count lines this way, so a lone \\r stays inside its line."""
    assert reader.read_lines("pkg/a.py") == ["one", "two\rthree", "four"]


def test_replaces_bytes_that_are_not_utf8(reader):
    assert reader.read_lines("pkg/latin1.py") == ["name = 'caf�'"]


def test_a_file_over_the_size_limit_is_not_read(reader):
    assert reader.is_file("pkg/big.py") is True
    assert reader.read_lines("pkg/big.py") is None


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "pkg/../../outside.txt",
        "/etc/passwd",
        "",
        "pkg\\a.py",
        "pkg/a.py\x00",
        "pkg/\ud800.py",
    ],
)
def test_refuses_paths_outside(reader, path):
    with pytest.raises(CheckoutError):
        reader.resolve(path)
    assert reader.read_lines(path) is None
    assert reader.is_file(path) is False


def test_missing_files_and_folders(reader):
    assert reader.read_lines("pkg/missing.py") is None
    assert reader.read_lines("pkg") is None
    assert reader.is_file("pkg") is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this system")
def test_a_fifo_is_not_read(reader):
    os.mkfifo(reader.root / "pkg/pipe.py")
    assert reader.is_file("pkg/pipe.py") is False
    assert reader.read_lines("pkg/pipe.py") is None


def test_refuses_a_link_out_of_the_checkout(reader, tmp_path):
    try:
        (reader.root / "pkg/link.py").symlink_to(tmp_path / "outside.txt")
    except OSError:
        pytest.skip("this machine can't create symbolic links")
    assert reader.read_lines("pkg/link.py") is None
    assert reader.is_file("pkg/link.py") is False


def test_follows_a_link_inside_the_checkout(reader):
    try:
        (reader.root / "pkg/alias.py").symlink_to(reader.root / "pkg/a.py")
    except OSError:
        pytest.skip("this machine can't create symbolic links")
    assert reader.read_lines("pkg/alias.py") == ["one", "two\rthree", "four"]
