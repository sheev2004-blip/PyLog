from pylog import (
    run_rules,
    AnalysisResult,
    analyze_log,
    RenderData,
    render_cli,
    Alert
)
    
# =========================
# RULE ENGINE TESTS
# =========================

def test_failed_login_rule_triggers():
    analysis = AnalysisResult(
        level_counts={"INFO": 0, "WARNING": 0, "ERROR": 0},
        message_counts={"failed login attempt": 5},
        top_messages=[("failed login attempt", 5)]
    )

    alerts = run_rules(analysis, threshold=3)

    assert len(alerts) == 1
    assert alerts[0].rule == "failed_login"
    assert alerts[0].severity == "HIGH"

# =========================
# INGESTION TESTS
# =========================

def test_ingestion_valid_ratio(tmp_path):
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-6-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
        "\n"
        "2026-06-12 ALERT Failed login\n"
        "bad line"
    )

    result = analyze_log(log_file, level_filter="ALL")

    ingestion = result.ingestion  

    assert ingestion.total_lines == 6
    assert ingestion.valid_lines == 3

    assert ingestion.skipped["malformed"] == 1
    assert ingestion.skipped["unknown_level"] == 1
    assert ingestion.skipped["blank"] == 1

    assert ingestion.valid_lines + sum(ingestion.skipped.values()) == ingestion.total_lines


def test_ingestion_blank_lines(tmp_path):
    log_file = tmp_path / "fake.log"

    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "\n"
        "   \n"
        "2026-06-12 ERROR Failed login\n"
    )

    result = analyze_log(log_file, level_filter="ALL")
    ingestion = result.ingestion

    assert ingestion.total_lines == 4
    assert ingestion.skipped["blank"] == 2

    assert ingestion.valid_lines == 2
    assert ingestion.valid_lines + sum(ingestion.skipped.values()) == ingestion.total_lines

    assert ingestion.skipped["blank"] >= 0
    assert ingestion.skipped["malformed"] >= 0
    assert ingestion.skipped["unknown_level"] >= 0

# =========================
# ANALYSIS TESTS
# =========================

def test_analyze_log_counts_valid_entries(tmp_path):
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    result = analyze_log(log_file, level_filter="ALL")

    analysis = result.analysis

    assert analysis.level_counts["INFO"] == 1
    assert analysis.level_counts["ERROR"] == 2
    assert analysis.level_counts["WARNING"] == 1

    assert analysis.message_counts["Login successful"] == 1
    assert analysis.message_counts["Failed login"] == 2
    assert analysis.message_counts["Low disk space"] == 1

# =========================
# EDGE CASE TESTS
# =========================

def test_edge_case_only_malformed(tmp_path):
    log_file = tmp_path / "fake.log"

    log_file.write_text(
    "bad line\n"
    "text\n"
    )

    result = analyze_log(log_file, level_filter="ALL")
    analysis = result.analysis

    assert analysis.level_counts["ERROR"] == 0
    assert result.ingestion.valid_lines == 0
    assert result.ingestion.skipped["malformed"] == 2

# =========================
# RENDERING TESTS
# =========================

def test_render_header(tmp_path):
    alerts = [
        Alert(
            rule="failed_login",
            severity="HIGH",
            message="3 failed login attempts detected"
        )
    ]
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    result = analyze_log(log_file, level_filter="ALL")

    analysis = result.analysis

    render_data = RenderData(
        filename=log_file.name,
        level_counts=analysis.level_counts,
        top_messages=analysis.top_messages,
        ingestion=result.ingestion,
        diagnostics=result.diagnostics,
        alerts=alerts
    )

    summary = render_cli(render_data, threshold=3, verbose=False)

    assert "fake.log" in summary
    assert "File:" in summary

def test_render_level_summary(tmp_path):
    alerts = [
        Alert(
            rule="failed_login",
            severity="HIGH",
            message="3 failed login attempts detected"
        )
    ]
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    result = analyze_log(log_file, level_filter="ALL")

    analysis = result.analysis

    render_data = RenderData(
        filename=log_file.name,
        level_counts=analysis.level_counts,
        top_messages=analysis.top_messages,
        ingestion=result.ingestion,
        diagnostics=result.diagnostics,
        alerts=alerts
    )

    summary = render_cli(render_data, threshold=3, verbose=False)
    lines = summary.splitlines()

    error_line = next(line for line in lines if "ERROR" in line)
    warning_line = next(line for line in lines if "WARNING" in line)
    info_line = next(line for line in lines if "INFO" in line)

    assert "ERROR" in summary
    assert "3" in error_line
    assert "WARNING" in summary
    assert "1" in warning_line
    assert "INFO" in summary
    assert "1" in info_line

def test_render_alert_block(tmp_path):
    alerts = [
        Alert(
            rule="failed_login",
            severity="HIGH",
            message="3 failed login attempts detected"
        )
    ]
    log_file = tmp_path / "fake.log"
    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    result = analyze_log(log_file, level_filter="ALL")

    analysis = result.analysis

    render_data = RenderData(
        filename=log_file.name,
        level_counts=analysis.level_counts,
        top_messages=analysis.top_messages,
        ingestion=result.ingestion,
        diagnostics=result.diagnostics,
        alerts=alerts
    )

    summary = render_cli(render_data, threshold=3, verbose=False)
    lines = summary.splitlines()

    start = next(i for i, line in enumerate(lines) if "HIGH" in line)

    header_line = lines[start]
    message_line = lines[start + 1]

    assert "HIGH" in header_line
    assert "failed_login" in header_line
    assert "3 failed login attempts detected" in message_line

def test_level_filter(tmp_path):
    log_file = tmp_path / "fake.log"

    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )
 
    result_error = analyze_log(log_file, level_filter="ERROR")

    assert result_error.analysis.level_counts == {"INFO": 0, "WARNING": 0, "ERROR": 2}
 
# =========================
# INTEGRATION TESTS
# =========================

def test_full_pipeline_integration(tmp_path):
    log_file = tmp_path / "fake.log"

    log_file.write_text(
        "2026-06-12 INFO Login successful\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 ERROR Failed login\n"
        "2026-06-12 WARNING Low disk space\n"
    )

    result = analyze_log(log_file, level_filter="ALL")
    analysis = result.analysis
    alerts = run_rules(result.analysis, threshold=3)

    render_data = RenderData(
        filename=log_file.name,
        level_counts=analysis.level_counts,
        top_messages=analysis.top_messages,
        ingestion=result.ingestion,
        diagnostics=result.diagnostics,
        alerts=alerts
    )

    summary = render_cli(render_data, threshold=3, verbose=False)

    assert "failed_login" in summary
    assert "HIGH" in summary
    assert "ERROR" in summary
    assert "File:" in summary

