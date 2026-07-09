from .models import RenderData

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
    if not top_messages:
        return ["No messages found"]
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
