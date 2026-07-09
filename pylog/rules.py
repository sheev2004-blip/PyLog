from .models import Alert 

FAILED_LOGIN_PHRASE = "failed login"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"


def make_failed_login_rule(threshold):
    def rule(analysis):
        for message, count in analysis.message_counts.items():
            if FAILED_LOGIN_PHRASE in message.lower() and count >= threshold:
                return Alert(
                    rule="failed_login",
                    severity=SEVERITY_HIGH,
                    message=f"{count} failed login attempts detected"
                )
        return None

    return rule

def error_volume_rule(analysis):
    error = analysis.level_counts["ERROR"]
    warning = analysis.level_counts["WARNING"]
    info = analysis.level_counts["INFO"]

    if error > warning + info:
         return Alert(
            rule="error_volume",
            severity=SEVERITY_HIGH,
            message="ERROR volume exceeds normal activity"
        )

    return None

def message_repetition_rule(analysis):
    messages = analysis.message_counts

    if len(messages) <= 1:
        return None

    total = sum(messages.values())
    max_message, max_count = max(messages.items(), key=lambda x: x[1])

    if max_count > total / 2:
       return Alert(
            rule="message_repetition",
            severity=SEVERITY_MEDIUM,
            message=f"'{max_message}' dominates logs ({max_count}/{total})"
        )


    return None

def run_rules(analysis, threshold):
    alerts = []

    rules = [
        make_failed_login_rule(threshold),
        error_volume_rule,
        message_repetition_rule
    ]

    for rule in rules:
        result = rule(analysis)
        if result:
            alerts.append(result)

    return alerts
