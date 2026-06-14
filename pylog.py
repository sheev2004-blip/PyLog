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
    try:
        with open(filename) as file:
            for line in file:
                if "ERROR" in line:
                    error_count += 1
                elif "WARNING" in line:
                    warning_count += 1
                elif "INFO" in line:
                    info_count += 1 
        return info_count, warning_count, error_count
    except FileNotFoundError:
        print("Error: File not found.")
        sys.exit(1)

def print_summary(info_count, warning_count, error_count):
    print("Log Summary")
    print("-----------")
    print("ERROR:", error_count)
    print("WARNING:", warning_count)
    print("INFO:", info_count)

def main():
    filename = get_filename()
    info_count, warning_count, error_count = analyze_log(filename)
    print_summary(info_count, warning_count, error_count)

if __name__ == "__main__":
    main()