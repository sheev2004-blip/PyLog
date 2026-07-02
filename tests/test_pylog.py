from pylog import run_rules, AnalysisResult, analyze_log, RenderData, render_cli, Alert


def test_failed_login_rule_triggers():
    analysis = AnalysisResult(
        level_counts={"INFO": 0, "WARNING": 0, "ERROR": 0},
        skipped_counts={"malformed": 0, "unknown_level": 0},
        message_counts={"failed login attempt": 5},
        top_messages=[("failed login attempt", 5)],
        total_lines= 5
    )

    alerts = run_rules(analysis, threshold=3)

    assert len(alerts) == 1
    assert alerts[0].rule == "failed_login"
    assert alerts[0].severity == "HIGH"


def test_error_volume_rule():
    analysis = AnalysisResult(
        level_counts={"INFO": 1, "WARNING": 1, "ERROR": 10},
        skipped_counts={"malformed": 0, "unknown_level": 0},
        message_counts={"a": 1},
        top_messages=[("a", 1)],
        total_lines=12
    )

    alerts = run_rules(analysis, threshold=3)

    assert any(a.rule == "error_volume" for a in alerts)


def test_message_repetition_rule():
    analysis = AnalysisResult(
        level_counts={"INFO": 0, "WARNING": 0, "ERROR": 0},
        skipped_counts={"malformed": 0, "unknown_level": 0},
        message_counts={"spam": 10, "normal": 1},
        top_messages=[("spam", 10), ("normal", 1)],
        total_lines= 11
    )

    alerts = run_rules(analysis, threshold=3)

    assert any(a.rule == "message_repetition" for a in alerts)


def test_no_alerts():
    analysis = AnalysisResult(
        level_counts={"INFO": 10, "WARNING": 2, "ERROR": 1},
        skipped_counts={"malformed": 0, "unknown_level": 0},
        message_counts={"ok": 5},
        top_messages=[("ok", 5)],
        total_lines= 13
    )

    alerts = run_rules(analysis, threshold=3)

    assert alerts == []


def test_render_includes_log_counts():
    render_data = RenderData(
        filename="sample.log",
        level_counts={"INFO": 2, "WARNING": 1, "ERROR": 3},
        skipped_counts={"malformed": 0, "unknown_level": 1},
        top_messages=[
            ("Failed login", 3),
            ("Login successful", 2),
            ("Low disk space", 1)
        ],
        alerts=[],
        total_lines=6
    )

    summary = render_cli(render_data, threshold=3)

    assert "File: sample.log" in summary
    assert "ERROR" in summary
    assert "3" in summary
    assert "WARNING" in summary
    assert "1" in summary
    assert "INFO" in summary
    assert "2" in summary
    assert "Malformed Lines" in summary
    assert "0" in summary
    assert "Unknown Levels" in summary
    assert "1" in summary


def test_render_includes_alerts():
    analysis = AnalysisResult(
        level_counts={"INFO": 2, "WARNING": 1, "ERROR": 3},
        skipped_counts={"malformed": 0, "unknown_level": 1},
        message_counts={
            "failed login attempt": 3,
            "low disk space": 1,
            "login successful": 2
        },
        top_messages=[
            ("failed login attempt", 3),
            ("low disk space", 1),
            ("login successful", 2)
        ],
        total_lines= 6
    )

    render_data = RenderData(
        filename="sample.log",
        level_counts=analysis.level_counts,
        skipped_counts=analysis.skipped_counts,
        top_messages=analysis.top_messages,
        alerts=run_rules(analysis, threshold=3),
        total_lines=6
    )

    summary = render_cli(render_data, threshold=3)

    assert "No alerts detected" not in summary


def test_render_sorts_message_counts_by_frequency():
    analysis = AnalysisResult(
        level_counts={"INFO": 0, "WARNING": 0, "ERROR": 0},
        skipped_counts={"malformed": 0, "unknown_level": 0},
        message_counts={
            "Low disk space": 1,
            "Failed login": 3,
            "Login successful": 2
        },
        top_messages=[
            ("Failed login", 3),
            ("Login successful", 2),
            ("Low disk space", 1)
        ],
        total_lines=6
    )

    render_data = RenderData(
        filename="sample.log",
        level_counts=analysis.level_counts,
        skipped_counts=analysis.skipped_counts,
        top_messages=analysis.top_messages,
        alerts=run_rules(analysis, threshold=3),
        total_lines=6
    )

    summary = render_cli(render_data, threshold=3)

    failed_index = summary.index("Failed login")
    login_index = summary.index("Login successful")
    disk_index = summary.index("Low disk space")

    assert failed_index < login_index < disk_index


def test_analyze_log_counts_valid_entries(tmp_path):
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
        "bad line\n"
        "2026-06-12 DEBUG Debug message\n"
    )

    analysis_result = analyze_log(
        log_file,
        verbose=False,
        level_filter="ALL"
    )

    assert analysis_result.level_counts["INFO"] == 1
    assert analysis_result.level_counts["WARNING"] == 1
    assert analysis_result.level_counts["ERROR"] == 2
    assert analysis_result.skipped_counts["malformed"] == 1
    assert analysis_result.skipped_counts["unknown_level"] == 1

    assert analysis_result.message_counts["Login successful"] == 1
    assert analysis_result.message_counts["Failed login"] == 2
    assert analysis_result.message_counts["Low disk space"] == 1
    assert "Debug message" not in analysis_result.message_counts


def test_analyze_log_handles_blank_lines(tmp_path):
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "\n"
        "2026-06-12 ERROR Failed login\n"
        "\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    analysis_result = analyze_log(
        log_file,
        verbose=False,
        level_filter="ALL"
    )

    assert analysis_result.level_counts["INFO"] == 1
    assert analysis_result.level_counts["WARNING"] == 1
    assert analysis_result.level_counts["ERROR"] == 1
    assert analysis_result.skipped_counts["malformed"] == 0
    assert analysis_result.skipped_counts["unknown_level"] == 0