import sys
import argparse
import dataclasses
from dataclasses import dataclass
from functools import partial
import json

@dataclass
class AnalysisResult: 
    level_counts: dict
    skipped_counts: dict
    message_counts: dict
    top_messages: list

@dataclass
class CLIOptions:
    logfile: str
    export: str | None
    csv_export: str | None
    json: str | None
    threshold: int
    verbose: bool
    level: str
    top: int | None

@dataclass
class Alert:
    rule: str
    severity: str
    message: str

@dataclass
class RenderData:
    filename: str
    level_counts: dict
    skipped_counts: dict
    top_messages: list
    alerts: list

@dataclass
class RuleContext:
    threshold: int

DEFAULT_EXPORT_FILENAME = "summary.txt"
DEFAULT_CSV_FILENAME = "data.csv"
DEFAULT_JSON_FILENAME = "data.json"
DEFAULT_THRESHOLD = 3
FAILED_LOGIN_PHRASE = "failed login"
VALID_LEVELS = {"INFO", "WARNING", "ERROR"}
DEFAULT_LEVEL= "ALL"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

def get_options():
    parser =  argparse.ArgumentParser(
        description="Analyze log files and generate summary reports."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--export", nargs="?", const=DEFAULT_EXPORT_FILENAME, help="Export the summary to a file")
    parser.add_argument("--csv_export", nargs="?", const=DEFAULT_CSV_FILENAME, help="Export data to a CSV file")
    parser.add_argument("--json", nargs="?", const=DEFAULT_JSON_FILENAME, help="Export alert data to JSON file" )
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Number of failed login attempts needed to trigger an alert")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--level", default=DEFAULT_LEVEL, choices=["ALL", "INFO", "WARNING", "ERROR"], help="Filter logs by level")
    parser.add_argument("--top", default=None, type=int, help="Display top N messages by frequency")

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    if args.top is not None and args.top < 1:
        parser.error("Top N must be a positive integer (>= 1).")
    return CLIOptions(
        logfile = args.logfile,
        export = args.export,
        csv_export = args.csv_export,
        json = args.json,
        threshold = args.threshold,
        verbose = args.verbose,
        level = args.level,
        top = args.top

    )

def analyze_log(filename, verbose, level_filter, top):
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

                if level_filter != DEFAULT_LEVEL and level != level_filter:
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

            sorted_messages = sorted(message_counts.items(), key=lambda item: item[1], reverse=True)
            
            if top is not None:
                sorted_messages = sorted_messages[:top]
            
        return AnalysisResult(
            level_counts = level_counts, 
            skipped_counts = skipped_counts, 
            message_counts = message_counts,
            top_messages=sorted_messages
        )
    except FileNotFoundError:
        print("Error: File not found:", filename)
        sys.exit(1)

def make_failed_login_rule(threshold):
    def rule(analysis_result):
        for message, count in analysis_result.message_counts.items():
            if FAILED_LOGIN_PHRASE in message.lower() and count >= threshold:
                return Alert(
                    rule="failed_login",
                    severity=SEVERITY_HIGH,
                    message=f"{count} failed login attempts detected"
                )
        return None

    return rule

def error_volume_rule(analysis_result):
    error = analysis_result.level_counts["ERROR"]
    warning = analysis_result.level_counts["WARNING"]
    info = analysis_result.level_counts["INFO"]

    if error > warning + info:
         return Alert(
            rule="error_volume",
            severity=SEVERITY_HIGH,
            message="ERROR volume exceeds normal activity"
        )

    return None

def message_repetition_rule(analysis_result):
    messages = analysis_result.message_counts

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

def run_rules(analysis_result, threshold):
    alerts = []

    rules = [
        make_failed_login_rule(threshold),
        error_volume_rule,
        message_repetition_rule
    ]

    for rule in rules:
        result = rule(analysis_result)
        if result:
            alerts.append(result)

    return alerts

def build_render_data(filename, analysis_result, alerts):
    return RenderData(
        filename=filename,
        level_counts=analysis_result.level_counts,
        skipped_counts=analysis_result.skipped_counts,
        top_messages=analysis_result.top_messages,
        alerts=alerts
    )


def render_cli(render_data):
    lines = []

    lines.append(f"Source File: {render_data.filename}")
    lines.append("")
    lines.append("Log Summary")
    lines.append("-----------")
    lines.append(f"ERROR: {render_data.level_counts['ERROR']}")
    lines.append(f"WARNING: {render_data.level_counts['WARNING']}")
    lines.append(f"INFO: {render_data.level_counts['INFO']}")
    lines.append(f"Malformed Lines Skipped: {render_data.skipped_counts['malformed']}")
    lines.append(f"Unknown Levels Skipped: {render_data.skipped_counts['unknown_level']}")
    lines.append('')
    lines.append("Message Counts:")
    lines.append("---------------")

    for message, count in render_data.top_messages:
        lines.append(f"{message}: {count}")
    lines.append('')


    lines.append("Suspicious Activity:")
    lines.append("--------------------")

    if render_data.alerts:
       for alert in render_data.alerts:
            lines.append(f"[{alert.severity}] {alert.rule}: {alert.message}")
    else:
        lines.append("None detected.")

    cli_summary = '\n'.join(lines)
    return cli_summary


def export_summary(summary, export_filename):
    with open(export_filename, "w") as file:
        file.write(summary)

def export_csv(top_messages, filename):

    with open(filename, "w") as file:
        file.write("Message,Count\n")
        for message, count in top_messages:
            file.write(f"{message},{count}\n")

def export_json(alerts, filename):
    alerts_list = []
    for alert in alerts:
        alerts_list.append(dataclasses.asdict(alert))
    with open(filename, "w") as file:
        json.dump(alerts_list, file)

def main():
    options = get_options()
    analysis_result = analyze_log(options.logfile, options.verbose, options.level, options.top)
    alerts = run_rules(analysis_result, options.threshold)
    render_data = build_render_data(options.logfile, analysis_result, alerts)
    summary = render_cli(render_data)
    print(summary)
    print(f"Failed login threshold used: {options.threshold}")
    if options.export: 
        export_summary(summary, options.export)
        print(f"Summary exported to {options.export}")
    if options.csv_export:
        export_csv(analysis_result.top_messages, options.csv_export)
        print(f"Data exported to {options.csv_export}")
    if options.json:
        export_json(alerts, options.json)
        print(f"Alerts data exported to {options.json}")

if __name__ == "__main__":
    main()