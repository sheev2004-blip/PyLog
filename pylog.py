import sys
import argparse
import dataclasses
from dataclasses import dataclass
import json


@dataclass
class IngestionStats:
    total_lines: int
    valid_lines: int
    valid_ratio: int
    skipped: dict

@dataclass
class IngestionDiagnostics:
    sample_errors: dict
    ingestion_health: str

@dataclass
class AnalysisResult: 
    level_counts: dict
    message_counts: dict
    top_messages: list

@dataclass
class LogAnalysis:
    analysis: AnalysisResult
    ingestion: IngestionStats
    diagnostics: IngestionDiagnostics

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
    top_messages: list
    alerts: list
    ingestion: IngestionStats
    diagnostics: IngestionDiagnostics


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
MAX_SAMPLES = 3

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

def analyze_log(filename, level_filter): 
    level_counts = {
    "INFO": 0,
    "WARNING": 0,
    "ERROR": 0
    }


    ingestion_stats = {
        "total_lines": 0,
        "valid_lines": 0,
        "skipped": {
            "blank": 0,
            "malformed": 0,
            "unknown_level": 0,
            "decode_errors": 0
        }
    }

    diagnostics = {
    "malformed": [],
    "unknown_level": [],
    "decode_errors": []
}

    message_counts = {}

    
    try:
        with open(filename, encoding="utf-8", errors="replace") as file:
            for line in file:
                ingestion_stats["total_lines"] += 1

                line = line.strip()

                if not line:
                    ingestion_stats["skipped"]["blank"] += 1
                    continue

                if "�" in line:
                    ingestion_stats["skipped"]["decode_errors"] += 1
                    if len(diagnostics["decode_errors"]) < MAX_SAMPLES:
                        diagnostics["decode_errors"].append(line)

                parts = line.split(maxsplit=2)

                if len(parts) < 3 or not parts[1] or not parts[2]:
                    ingestion_stats["skipped"]["malformed"] += 1
                    if len(diagnostics["malformed"]) < MAX_SAMPLES:
                        diagnostics["malformed"].append(line)
                    continue

                level = parts[1].strip().upper()

                if level not in VALID_LEVELS:
                    ingestion_stats["skipped"]["unknown_level"] += 1
                    if len(diagnostics["unknown_level"]) < MAX_SAMPLES:
                        diagnostics["unknown_level"].append(line)
                    continue
                ingestion_stats["valid_lines"] += 1
                if level_filter != DEFAULT_LEVEL and level != level_filter.upper():
                    continue

                message = parts[2].strip() if parts[2] else ""

                message_counts[message] = message_counts.get(message, 0) + 1

                if level == "ERROR":
                    level_counts["ERROR"] += 1
                elif level == "WARNING":
                    level_counts["WARNING"] += 1
                elif level == "INFO":
                    level_counts["INFO"] += 1 
            valid_ratio = (
                ingestion_stats["valid_lines"] / ingestion_stats["total_lines"]
                if ingestion_stats["total_lines"] > 0
                    else 0
            )
            if valid_ratio >= 0.9:
                health = "HIGH"
            elif valid_ratio >= 0.8:
                health = "MEDIUM"
            else:
                health = "LOW"
            sorted_messages = sorted(message_counts.items(), key=lambda item: item[1], reverse=True)
            
        return LogAnalysis(
            AnalysisResult(level_counts = level_counts, 
            message_counts = message_counts,
            top_messages=sorted_messages), 
            IngestionStats(
            total_lines=ingestion_stats["total_lines"],
            valid_lines=ingestion_stats["valid_lines"],
            valid_ratio = valid_ratio,
            skipped=ingestion_stats["skipped"]
            ),
            IngestionDiagnostics(
            sample_errors=diagnostics,
            ingestion_health=health
            )
        )
    except FileNotFoundError:
        print("Error: File not found:", filename)
        sys.exit(1)

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

def run_rules(log_analysis, threshold):
    alerts = []

    rules = [
        make_failed_login_rule(threshold),
        error_volume_rule,
        message_repetition_rule
    ]

    for rule in rules:
        result = rule(log_analysis)
        if result:
            alerts.append(result)

    return alerts

def build_render_data(filename, log_analysis, alerts, top):
    top_messages = log_analysis.analysis.top_messages
    if top is not None:
        top_messages = top_messages[:top]

    return RenderData(
        filename=filename,
        level_counts=log_analysis.analysis.level_counts,
        ingestion=log_analysis.ingestion,
        top_messages=top_messages,
        alerts=alerts,
        diagnostics=log_analysis.diagnostics
    )

def format_ingestion_summary_block(stats):
    lines = ["Ingestion Summary", "------------------------------------",
              f"Ingestion: {stats.total_lines} lines ({stats.valid_ratio:.0%} clean, {stats.total_lines - stats.valid_lines} skipped)"]
    return lines

def format_ingestion_verbose(diagnostics, stats):
    lines = ["Ingestion Details:", "-------------------"]

    skipped = stats.skipped
    examples = diagnostics.sample_errors

    for key, value in skipped.items():
        lines.append(f"- {key}: {value}")

    lines.append("")

    lines.append("Malformed Examples:")

    lines.append("")

    if examples["malformed"]:
        for malformed in examples["malformed"]:
            lines.append(malformed)
    else:
        lines.append("None")

    lines.append("")
        
    lines.append("Unknown Level Examples:")

    lines.append("")

    if examples["unknown_level"]:
        for unknown in examples["unknown_level"]:
            lines.append(unknown)
    else:
        lines.append("None")

    lines.append("")

    lines.append("Decode Error Examples:")

    lines.append("")

    if examples["decode_errors"]:
        for decode in examples["decode_errors"]:
            lines.append(decode)
    else:
        lines.append("None")

    return lines


def format_message_table(top_messages):
    width = max(len(m) for m, _ in top_messages)

    lines = ["Message Frequency", "------------------------------------"]

    for message, count in top_messages:
        lines.append(f"{message:<{width}} {count:>5}")

    return lines

def format_alerts(alerts):
    lines = ["Alerts", "------------------------------------"]

    if alerts:
        for alert in alerts:
            lines.append(f"{alert.severity} ALERT: {alert.rule}")
            lines.append(alert.message)
    else:
        lines.append("No alerts detected")

    return lines

def render_cli(render_data, threshold, verbose):
    lines = []

    lines.append("====================================")
    lines.append("PyLog Analysis Report")
    lines.append("")
    lines.append("Mode: default | verbose")
    lines.append("====================================")
    lines.append("")
    lines.append(f"File: {render_data.filename}")
    lines.append("")
    lines.append(f"{render_data.ingestion.total_lines} lines processed")
    lines.append(f"{render_data.ingestion.valid_lines} valid lines")
    lines.append(f"{len(render_data.alerts)} alert(s) | threshold = {threshold}")
    
    lines.append("")
    lines.append("Log Summary")
    lines.append("------------------------------------")
    lines.append(f"{'ERROR':<17}{render_data.level_counts['ERROR']:>5}")
    lines.append(f"{'WARNING':<17}{render_data.level_counts['WARNING']:>5}")
    lines.append(f"{'INFO':<17}{render_data.level_counts['INFO']:>5}")
    lines.append("")
    lines.extend(format_message_table(render_data.top_messages))
    lines.append("")
    lines.extend(format_alerts(render_data.alerts))
    lines.append("")
    lines.extend(format_ingestion_summary_block(render_data.ingestion))
    lines.append("")

    if verbose:
        lines.extend(
            format_ingestion_verbose(
                render_data.diagnostics,
                render_data.ingestion
            )
        )

    cli_summary = '\n'.join(lines)
    return cli_summary


def export_summary(summary, export_filename):
    with open(export_filename, "w", encoding="utf-8", errors="replace") as file:
        file.write(summary)

def export_csv(top_messages, filename, top):
    if top is not None:
        top_messages = top_messages[:top]
    with open(filename, "w", encoding="utf-8", errors="replace") as file:
        file.write("Message,Count\n")
        for message, count in top_messages:
            file.write(f"{message},{count}\n")

def export_json(alerts, filename):
    output = {
        "version": 1,
        "file": filename,
        "alerts": [dataclasses.asdict(a) for a in alerts]
    }

    with open(filename, "w", encoding="utf-8", errors="replace") as file:
        json.dump(output, file, indent=2)

def main():
    options = get_options()
    analysis_result = analyze_log(options.logfile, options.level)
    alerts = run_rules(analysis_result, options.threshold)
    render_data = build_render_data(options.logfile, analysis_result, alerts, options.top)
    summary = render_cli(render_data, options.threshold, options.verbose)
    print(summary)

    if options.export: 
        export_summary(summary, options.export)
        print(f"Exported: {options.export}")
    if options.csv_export:
        export_csv(analysis_result.top_messages, options.csv_export, options.top)
        print(f"Data exported: {options.csv_export}")
    if options.json:
        export_json(alerts, options.json)
        print(f"Alerts data exported: {options.json}")
    if alerts:
        exit(1)
    else: 
        exit(0)

if __name__ == "__main__":
    main()