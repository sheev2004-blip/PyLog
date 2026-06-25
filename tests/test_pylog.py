from pylog import detect_suspicious_activity, build_summary, analyze_log

def test_detects_failed_logins_at_threshold():
    message_counts = {
        "Failed login": 3,
        "Login successful": 1
    }

    result = detect_suspicious_activity(message_counts, 3)

    assert result == [("Failed login", 3)]

def test_does_not_detect_failed_logins_below_threshold():
    message_counts = {
        "Failed login": 2,
        "Login successful": 1
    }

    result = detect_suspicious_activity(message_counts, 3)

    assert result == []

def test_detects_failed_logins_case_insensitive():
    message_counts = {
        "FAILED LOGIN": 4
    }

    result = detect_suspicious_activity(message_counts, 3)

    assert result == [("FAILED LOGIN", 4)]

def test_build_summary_includes_log_counts():
    summary = build_summary(
        filename = "sample.log",
        level_counts = {
            "INFO": 2,
            "WARNING": 1,
            "ERROR": 3
        },
        skipped_counts = {
            "malformed": 0,
            "unknown_level": 1
        },
        message_counts = {
            "Failed login": 3,
            "Login successful": 2,
            "Low disk space": 1 
        },
        suspicious_activity = [("Failed login", 3)]
    )

    assert "Source File: sample.log" in summary
    assert "ERROR: 3" in summary
    assert "WARNING: 1" in summary
    assert "INFO: 2" in summary
    assert "Malformed Lines Skipped: 0" in summary
    assert "Unknown Levels Skipped: 1" in summary

def test_build_summary_includes_suspicious_activity():
    summary = build_summary(
        filename = "sample.log",
        level_counts = {
            "INFO": 1,
            "WARNING": 0,
            "ERROR": 0
        },
        skipped_counts = {
            "malformed": 0,
            "unknown_level": 0
        },
        message_counts = {"Login successful": 1},
        suspicious_activity = []
    )

    assert "Suspicious Activity:" in summary 
    assert "None detected." in summary

def test_build_summary_sorts_message_counts_by_frequency():
    summary = build_summary(
        filename="sample.log",
        level_counts={
            "INFO": 0,
            "WARNING": 0,
            "ERROR": 0
        },
        skipped_counts={
            "malformed": 0,
            "unknown_level": 0
        },
        message_counts={
            "Low disk space": 1,
            "Failed login": 3,
            "Login successful": 2
        },
        suspicious_activity=[]
    )

    failed_index = summary.index("Failed login: 3")
    login_index = summary.index("Login successful: 2")
    disk_index = summary.index("Low disk space: 1")

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
    analysis_result = analyze_log(log_file, verbose=False)
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
    analysis_result = analyze_log(log_file, verbose=False)

    assert analysis_result.level_counts["INFO"] == 1
    assert analysis_result.level_counts["WARNING"] == 1
    assert analysis_result.level_counts["ERROR"] == 1
    assert analysis_result.skipped_counts["malformed"] == 0
    assert analysis_result.skipped_counts["unknown_level"] == 0


