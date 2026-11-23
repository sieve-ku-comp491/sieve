"""The Markdown report format."""

from app.reports import Location, MarkdownFormat, Report, ReportFormat, ReportText, Severity
from app.reports.formats import default_formats

SEVERITY = Severity(
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    score=9.3,
    level="critical",
)


def make_report(**changes) -> Report:
    text = ReportText(
        version=2,
        source="reviewer_edit",
        title="SQL injection in the login form",
        summary="The login route builds its query with string formatting.",
        impact="An attacker can log in as any user.",
        steps_to_reproduce=("Open the login page.", "Enter admin' -- as the user name."),
        fix="Pass the values as query parameters.",
        references=(
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ),
        severity=SEVERITY,
        locations=(Location("app/views.py", 52, 59),),
        author="researcher",
    )
    return Report.of("report-1", ("finding-1",), text.with_fields(**changes), "draft")


def test_the_layout_of_docs_interfaces():
    assert MarkdownFormat().render(make_report()) == (
        "# SQL injection in the login form\n"
        "\n"
        "Severity: Critical (CVSS 4.0 score 9.3)\n"
        "Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N\n"
        "Location: app/views.py, lines 52 to 59\n"
        "\n"
        "## Summary\n"
        "\n"
        "The login route builds its query with string formatting.\n"
        "\n"
        "## Impact\n"
        "\n"
        "An attacker can log in as any user.\n"
        "\n"
        "## Steps to reproduce\n"
        "\n"
        "1. Open the login page.\n"
        "2. Enter admin' -- as the user name.\n"
        "\n"
        "## Fix\n"
        "\n"
        "Pass the values as query parameters.\n"
        "\n"
        "## References\n"
        "\n"
        "- https://cwe.mitre.org/data/definitions/89.html\n"
        "- https://cheatsheetseries.owasp.org/cheatsheets/"
        "SQL_Injection_Prevention_Cheat_Sheet.html\n"
    )


def test_a_score_always_has_one_decimal_and_the_level_is_capitalized():
    severity = Severity("CVSS:4.0/AV:N", 7.0, "high")
    assert "Severity: High (CVSS 4.0 score 7.0)" in MarkdownFormat().render(
        make_report(severity=severity)
    )


def test_a_title_is_one_line_and_a_step_keeps_its_lines_under_its_number():
    report = make_report(
        title="SQL injection\n\nin   the login form",
        steps_to_reproduce=("Send:\n\n    POST /login\n    name=x", "Read the response."),
    )
    text = MarkdownFormat().render(report)
    assert text.startswith("# SQL injection in the login form\n")
    assert "1. Send:\n\n       POST /login\n       name=x\n2. Read the response.\n" in text


def test_markdown_is_the_default_format_and_a_format_has_a_name_and_an_extension():
    formats = default_formats()
    assert list(formats) == ["markdown"]
    format: ReportFormat = formats["markdown"]
    assert (format.name, format.file_extension) == ("markdown", ".md")


def test_every_location_has_its_own_line_and_one_line_is_singular():
    report = make_report(
        locations=(Location("app/views.py", 46, 46), Location("app/db.py", 10, 12))
    )
    text = MarkdownFormat().render(report)
    assert "Location: app/views.py, line 46\nLocation: app/db.py, lines 10 to 12\n\n" in text
