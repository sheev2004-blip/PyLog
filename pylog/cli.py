import argparse

from .models import CLIOptions
from pylog import analyze_log, run_rules, render_cli
from .render import build_render_data
from .export import export_csv, export_json, export_summary

DEFAULT_EXPORT_FILENAME = "summary.txt"
DEFAULT_CSV_FILENAME = "data.csv"
DEFAULT_JSON_FILENAME = "data.json"
DEFAULT_LEVEL= "ALL"
DEFAULT_THRESHOLD = 3

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

def main():
    options = get_options()
    analysis_result = analyze_log(options.logfile, options.level)
    alerts = run_rules(analysis_result.analysis, options.threshold)
    render_data = build_render_data(options.logfile, analysis_result, alerts, options.top)
    summary = render_cli(render_data, options.threshold, options.verbose)
    print(summary)

    if options.export: 
        if not options.export.endswith(".txt"):
            options.export += ".txt"
        export_summary(summary, options.export)
        print(f"Exported: {options.export}")
    if options.csv_export:
        if not options.csv_export.endswith(".csv"):
            options.csv_export += ".csv"
        export_csv(analysis_result.analysis.top_messages, options.csv_export, options.top)
        print(f"Data exported: {options.csv_export}")
    if options.json:
        if not options.json.endswith(".json"):
            options.json += ".json"
        export_json(alerts, options.logfile, options.json)
        print(f"Alerts data exported: {options.json}")
    if alerts:
        exit(1)
    else: 
        exit(0)

if __name__ == "__main__":
    main()