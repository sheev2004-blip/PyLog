# PyLog

PyLog is a Python command-line log analysis tool that reads a log file, summarizes log levels, reports repeated messages, detects simple suspicious activity patterns, and optionally exports the results to a text report.

## Overview

PyLog was built as a personal Python project to practice file processing, command-line arguments, dictionaries, error handling, Git/GitHub workflow, and basic cybersecurity-oriented log analysis.

The program currently supports logs formatted as:

```text
DATE LEVEL MESSAGE
```

Example:

```text
2026-06-12 INFO Login successful
2026-06-12 ERROR Failed login
2026-06-12 WARNING Low disk space
```

## Features

* Reads a log file from the command line
* Counts `INFO`, `WARNING`, and `ERROR` entries
* Skips blank lines
* Skips malformed log lines
* Skips unknown log levels
* Handles missing files with a clear error message
* Counts repeated log messages
* Sorts message counts from most common to least common
* Detects repeated failed login messages
* Optionally exports the summary to a text file
* Uses argparse for command-line options
* Allows configurable failed-login threshold

## Technologies Used

* Python
* Git
* GitHub
* Command-line interface

## Usage

Run PyLog with a log file:

```bash
python pylog.py sample.log
```

This prints a summary to the terminal.

Export to the default report file:

```bash
python pylog.py sample.log --export
```

This creates or updates:

```text
summary.txt
```

Export to a custom report file:

```bash
python pylog.py sample.log --export report.txt
```

Set a custom failed login threshold:

```bash
python pylog.py sample.log --threshold 5
```

Add details about malformed lines and unknown log levels as they are encountered:

```bash
python pylog.py sample.log --verbose
```

## Example Output

```text
Source File: sample.log

Log Summary
-----------
ERROR: 3
WARNING: 1
INFO: 2
Malformed Lines Skipped: 0
Unknown Levels Skipped: 0

Message Counts:
---------------
Failed login: 3
Login successful: 1
Low disk space: 1

Suspicious Activity:
--------------------
Failed login occurred 3 times
```

## Suspicious Activity Detection

PyLog currently flags repeated failed login messages when they occur at least three times, or however many times indicated by the user's custom threshold.

Current detection rule:

```text
Message contains "failed login" and count >= 3 (or custom number)
```

This is a simple rule-based detection feature intended to demonstrate basic log analysis and security monitoring concepts.

## Testing

PyLog includes automated tests using `pytest`.

Run the test suite from the project root:

```bash
python -m pytest

## Project Structure

```text
pylog/
├── pylog.py
├── sample.log
├── README.md
└── .gitignore
```

## Concepts Demonstrated

* File input and output
* Command-line argument handling
* Error handling with `try` / `except`
* String parsing and validation
* Dictionaries for frequency counting
* Sorting data
* Basic suspicious activity detection
* Function-based program organization
* Git/GitHub project workflow

## Current Limitations

* Expects logs to follow the `DATE LEVEL MESSAGE` format
* Supports only `INFO`, `WARNING`, and `ERROR` log levels
* Suspicious activity detection is currently rule-based and limited to repeated failed login messages
* Does not currently support real Linux authentication log formats or multiple log formats

## Future Improvements

* Add support for additional log levels such as `DEBUG` and `CRITICAL`
* Add more suspicious activity rules
* Support additional log formats
* Add CSV export


