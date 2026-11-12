"""The fingerprint and context hash of docs/finding-format.md."""

from app.adapters import context_hash, fingerprint, normalize


def test_normalize_ignores_formatting():
    before = ["    return render(request,'login')", "", "   "]
    after = ['    return render(request, "login")']
    assert normalize(before) == normalize(after) == 'returnrender(request,"login")'


def test_fingerprint_parts():
    lines = ["x = query(a)"]
    base = fingerprint("semgrep", "rule", "app.py", lines, 0)
    assert base.startswith("v1:") and len(base) == 3 + 32
    assert fingerprint("semgrep", "rule", "app.py", ["x=query(a)"], 0) == base
    assert fingerprint("bandit", "rule", "app.py", lines, 0) != base
    assert fingerprint("semgrep", "other", "app.py", lines, 0) != base
    assert fingerprint("semgrep", "rule", "lib.py", lines, 0) != base
    assert fingerprint("semgrep", "rule", "app.py", ["x = query(b)"], 0) != base
    assert fingerprint("semgrep", "rule", "app.py", lines, 1) != base


def test_context_hash_window():
    lines = [f"line{i}" for i in range(1, 41)]
    base = context_hash(lines, 20, 20)
    assert base.startswith("c1:")
    changed_near = list(lines)
    changed_near[9] = "changed"  # line 10, inside the 10 lines before line 20
    changed_far = list(lines)
    changed_far[8] = "changed"  # line 9, outside the window
    assert context_hash(changed_near, 20, 20) != base
    assert context_hash(changed_far, 20, 20) == base
    assert context_hash(lines, 1, 1) == context_hash(lines[:11], 1, 1)
