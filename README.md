# PyLog

A Python command-line log analysis tool that summarizes log levels, validates log line format, handles missing files, and reports message frequency. Also detects suspicious activity based on thresholds.

## Current Features

- Accepts a log file as a command-line argument
- Counts INFO, WARNING, and ERROR entries
- Skips malformed log lines
- Skips unknown log levels
- Handles missing files gracefully
- Counts repeated log messages
- Suspicious activity detection

