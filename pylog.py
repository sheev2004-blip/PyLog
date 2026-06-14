import sys

error_count = 0
warning_count = 0
info_count = 0

if len(sys.argv) != 2:
    print("Usage: python pylog.py <logfile>")
    sys.exit(1)

filename = sys.argv[1]
try:
    with open(filename) as file:
        for line in file:
            if "ERROR" in line:
                error_count += 1
            elif "WARNING" in line:
                warning_count += 1
            elif "INFO" in line:
                info_count += 1 
    print("Log Summary")
    print("-----------")
    print("ERROR: ", error_count)
    print("WARNING: ", warning_count)
    print("INFO: ", info_count)
except FileNotFoundError:
    print("Error: File not found.")
    sys.exit(1)