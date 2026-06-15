import sys

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
                parts = line.split(maxsplit=2)

                if len(parts) < 3:
                    malformed_count += 1
                    print("Skipping malformed line:", line.strip())
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
        print("Error: File not found.")
        sys.exit(1)

def print_summary(info_count, warning_count, error_count, malformed_count, unknown_count, message_counts):
    print("Log Summary")
    print("-----------")
    print("ERROR:", error_count)
    print("WARNING:", warning_count)
    print("INFO:", info_count)
    print("Malformed Lines Skipped:", malformed_count)
    print("Unknown Levels Skipped:", unknown_count)
    print("Message Counts:")
    print("---------------")

    sorted_messages = sorted(message_counts.items(), key=lambda item: item[1], reverse=True)

    for message, count in sorted_messages:
        print(f"{message}: {count}")

def main():
    filename = get_filename()
    info_count, warning_count, error_count, malformed_count, unknown_count, message_counts = analyze_log(filename)
    print_summary(info_count, warning_count, error_count, malformed_count, unknown_count, message_counts)

if __name__ == "__main__":
    main()