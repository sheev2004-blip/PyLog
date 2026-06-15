import sys

from matplotlib import lines

FAILED_LOGIN_THRESHOLD = 3

def get_options():
    export_enabled = False

    if len(sys.argv) == 2:
        return sys.argv[1], export_enabled, None 
    elif len(sys.argv) == 3 and sys.argv[2] == "--export":
        export_enabled = True
        return sys.argv[1], export_enabled, "summary.txt"
    elif len(sys.argv) == 4 and sys.argv[2] == "--export":
        export_enabled = True
        return sys.argv[1], export_enabled, sys.argv[3]
    else:
        print("Usage: python pylog.py <logfile> [--export [output_file]]")
        sys.exit(1)

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

def build_summary(filename, info_count, warning_count, error_count, malformed_count, unknown_count, message_counts, suspicious_activity, export_filename):
    lines = []
    lines.append(f"Source File: {filename}")
    lines.append("")
    lines.append("Log Summary")
    lines.append("-----------")
    lines.append(f"ERROR: {error_count}")
    lines.append(f"WARNING: {warning_count}")
    lines.append(f"INFO: {info_count}")
    lines.append(f"Malformed Lines Skipped: {malformed_count}")
    lines.append(f"Unknown Levels Skipped: {unknown_count}")
    lines.append('')
    lines.append("Message Counts:")
    lines.append("---------------")

    sorted_messages = sorted(message_counts.items(), key=lambda item: item[1], reverse=True)

    for message, count in sorted_messages:
        lines.append(f"{message}: {count}")
    lines.append('')

    lines.append("Suspicious Activity:")
    lines.append("--------------------")
    if suspicious_activity:
        for message, count in suspicious_activity:
            lines.append(f"{message} occurred {count} times")
    else:
        lines.append("None detected.")

    summary = '\n'.join(lines)
    return summary

def print_summary(summary):
    print(summary)

def export_summary(summary, export_filename):
    with open(export_filename, "w") as file:
        file.write(summary)

def main():
    filename, export_enabled, export_filename = get_options()
    info_count, warning_count, error_count, malformed_count, unknown_count, message_counts = analyze_log(filename)
    suspicious_activity = detect_suspicious_activity(message_counts)
    summary = build_summary(filename, info_count, warning_count, error_count, malformed_count, unknown_count, message_counts, suspicious_activity, export_filename)
    print_summary(summary)
    if export_enabled: 
        export_summary(summary, export_filename)
        print(f"Summary exported to {export_filename}")
if __name__ == "__main__":
    main()