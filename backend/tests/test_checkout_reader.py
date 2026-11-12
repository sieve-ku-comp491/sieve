"""Reading a checkout without leaving it."""

import pytest

from app.checkout import CheckoutError, CheckoutReader


@pytest.fixture
def reader(tmp_path):
    root = tmp_path / "checkout"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg/a.py").write_bytes(b"one\r\ntwo\rthree\nfour\n")
    (root / "pkg/latin1.py").write_bytes(b"name = 'caf\xe9'\n")
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    return CheckoutReader(root)


def test_reads_lines_with_any_line_break(reader):
    assert reader.read_lines("pkg/a.py") == ["one", "two", "three", "four"]


def test_replaces_bytes_that_are_not_utf8(reader):
    assert reader.read_lines("pkg/latin1.py") == ["name = 'caf�'"]


@pytest.mark.parametrize(
    "path", ["../outside.txt", "pkg/../../outside.txt", "/etc/passwd", "", "pkg\\a.py"]
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
    assert reader.read_lines("pkg/alias.py") == ["one", "two", "three", "four"]
