import sys

FAILED_LOGIN_THRESHOLD = 3

def get_filename():
    if len(sys.argv) != 2:
        print("Usage: python pylog.py <logfile>")
        sys.exit(1)
    return sys.argv[1]

def analyze_log(filename):
    error_count = 0
    warning_count = 0
    info_count = 0
    malformed_count = 0
    unknown_count = 0
    valid_levels = {"INFO", "WARNING", "ERROR"}
    message_counts = {}
    try:
        with open(filename) as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(maxsplit=2)

                if len(parts) < 3:
                    malformed_count += 1
                    print("Skipping malformed line:", line)
                    continue

                level = parts[1]

                if level not in valid_levels:
                    unknown_count += 1
                    print("Skipping unknown log level:", level)
                    continue

                message = parts[2].strip()
                if message not in message_counts:
                    message_counts[message] = 1
                else:
                    message_counts[message] += 1

                if level == "ERROR":
                    error_count += 1
                elif level == "WARNING":
                    warning_count += 1
                elif level == "INFO":
                    info_count += 1 
        return info_count, warning_count, error_count, malformed_count, unknown_count, message_counts
    except FileNotFoundError:
        print("Error: File not found:", filename)
        sys.exit(1)

def detect_suspicious_activity(message_counts):
    suspicious_activity = []
    for message, count in message_counts.items():
        if "failed login" in message.lower() and count >= FAILED_LOGIN_THRESHOLD:
            suspicious_activity.append((message, count))
    return suspicious_activity

def print_summary(info_count, warning_count, error_count, malformed_count, unknown_count, message_counts, suspicious_activity):
    print("Log Summary")
    print("-----------")
    print("ERROR:", error_count)
    print("WARNING:", warning_count)
    print("INFO:", info_count)
    print("Malformed Lines Skipped:", malformed_count)
    print("Unknown Levels Skipped:", unknown_count)
    print()
    print("Message Counts:")
    print("---------------")

    sorted_messages = sorted(message_counts.items(), key=lambda item: item[1], reverse=True)

    for message, count in sorted_messages:
        print(f"{message}: {count}")
    print()
    print("Suspicious Activity:")
    print("-------------------")
    if suspicious_activity:
        for message, count in suspicious_activity:
            print(f"{message} occurred {count} times")
    else:
        print("None detected.")


def main():
    filename = get_filename()
    info_count, warning_count, error_count, malformed_count, unknown_count, message_counts = analyze_log(filename)
    suspicious_activity = detect_suspicious_activity(message_counts)
    print_summary(info_count, warning_count, error_count, malformed_count, unknown_count, message_counts, suspicious_activity)

if __name__ == "__main__":
    main()