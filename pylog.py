import sys
import argparse

DEFAULT_EXPORT_FILENAME = "summary.txt"
DEFAULT_THRESHOLD = 3
FAILED_LOGIN_PHRASE = "failed login"
VALID_LEVELS = {"INFO", "WARNING", "ERROR"}

def get_options():
    parser =  argparse.ArgumentParser(
        description="Analyze log files and generate summary reports."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--export", nargs="?", const=DEFAULT_EXPORT_FILENAME, help="Export the summary to a file")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Number of failed login attempts needed to trigger an alert")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    return args.logfile, args.export is not None, args.export, args.threshold, args.verbose

def analyze_log(filename, verbose):
    level_counts = {
    "INFO": 0,
    "WARNING": 0,
    "ERROR": 0
    }

    skipped_counts = {
    "malformed": 0,
    "unknown_level": 0
}
    message_counts = {}
    
    try:
        with open(filename) as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(maxsplit=2)

                if len(parts) < 3:
                    skipped_counts["malformed"] += 1
                    if verbose:
                        print("Skipping malformed line:", line)
                    continue

                level = parts[1]

                if level not in VALID_LEVELS:
                    skipped_counts["unknown_level"] += 1
                    if verbose:
                        print("Skipping unknown log level:", level)
                    continue

                message = parts[2].strip()
                if message not in message_counts:
                    message_counts[message] = 1
                else:
                    message_counts[message] += 1

                if level == "ERROR":
                    level_counts["ERROR"] += 1
                elif level == "WARNING":
                    level_counts["WARNING"] += 1
                elif level == "INFO":
                    level_counts["INFO"] += 1 
        return level_counts, skipped_counts, message_counts
    except FileNotFoundError:
        print("Error: File not found:", filename)
        sys.exit(1)

def detect_suspicious_activity(message_counts, threshold):
    suspicious_activity = []
    for message, count in message_counts.items():
        if FAILED_LOGIN_PHRASE in message.lower() and count >= threshold:
            suspicious_activity.append((message, count))
    return suspicious_activity

def build_summary(filename, level_counts, skipped_counts, message_counts, suspicious_activity):
    lines = []
    lines.append(f"Source File: {filename}")
    lines.append("")
    lines.append("Log Summary")
    lines.append("-----------")
    lines.append(f"ERROR: {level_counts['ERROR']}")
    lines.append(f"WARNING: {level_counts['WARNING']}")
    lines.append(f"INFO: {level_counts['INFO']}")
    lines.append(f"Malformed Lines Skipped: {skipped_counts['malformed']}")
    lines.append(f"Unknown Levels Skipped: {skipped_counts['unknown_level']}")
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

def export_summary(summary, export_filename):
    with open(export_filename, "w") as file:
        file.write(summary)

def main():
    filename, export_enabled, export_filename, threshold, verbose = get_options()
    level_counts, skipped_counts, message_counts = analyze_log(filename, verbose)
    suspicious_activity = detect_suspicious_activity(message_counts, threshold)
    summary = build_summary(filename, level_counts, skipped_counts, message_counts, suspicious_activity)
    print(summary)
    if export_enabled: 
        export_summary(summary, export_filename)
        print(f"Summary exported to {export_filename}")
    print(f"Failed login threshold used: {threshold}")
if __name__ == "__main__":
    main()