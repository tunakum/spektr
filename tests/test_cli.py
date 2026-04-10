"""Tests for CLI commands and help output."""

from typer.testing import CliRunner

from spektr.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_version_short_flag() -> None:
    result = runner.invoke(app, ["-v"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "spektr" in result.output
    assert "Search" in result.output or "search" in result.output


def test_help_flag() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "severity" in result.output
    assert "limit" in result.output
    assert "sort" in result.output


def test_help_shows_cve_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "cve" in result.output.lower()


def test_help_shows_clear_cache() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "clear-cache" in result.output


def test_help_shows_config() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--config" in result.output


def test_help_shows_output() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--output" in result.output


def test_query_rejects_purely_numeric() -> None:
    result = runner.invoke(app, ["123"])
    assert result.exit_code != 0
    assert "Invalid query" in result.output


def test_query_rejects_single_char() -> None:
    result = runner.invoke(app, ["a"])
    assert result.exit_code != 0
    assert "Invalid query" in result.output


def test_query_rejects_whitespace_only() -> None:
    result = runner.invoke(app, ["   "])
    assert result.exit_code != 0


def test_query_rejects_empty_string() -> None:
    result = runner.invoke(app, [""])
    assert result.exit_code != 0


def test_query_accepts_long_input() -> None:
    """Long but valid query should not crash."""
    result = runner.invoke(app, ["a" * 100])
    # Should either work or fail gracefully, not crash
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_query_with_special_chars_no_crash() -> None:
    """Injection-like input should not crash."""
    result = runner.invoke(app, ["nginx; rm -rf /"])
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_limit_zero() -> None:
    """--limit 0 should not crash."""
    result = runner.invoke(app, ["log4j", "--limit", "0"])
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_limit_negative() -> None:
    """--limit -1 should not crash."""
    result = runner.invoke(app, ["log4j", "--limit", "-1"])
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_cve_no_argument() -> None:
    """spektr cve without ID should show error."""
    result = runner.invoke(app, ["cve"])
    assert result.exit_code != 0


def test_cve_invalid_id() -> None:
    """Fetching a garbage CVE ID should fail gracefully."""
    result = runner.invoke(app, ["cve", "NOT-A-CVE"])
    # Should exit with error, not crash
    assert (
        result.exit_code != 0
        or "not found" in result.output.lower()
        or "error" in result.output.lower()
    )
