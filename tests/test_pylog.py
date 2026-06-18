from pylog import detect_suspicious_activity

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