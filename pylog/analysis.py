import sys

from .models import LogAnalysis, AnalysisResult, IngestionDiagnostics, IngestionStats

MAX_SAMPLES = 3
DEFAULT_LEVEL= "ALL"
VALID_LEVELS = {"INFO", "WARNING", "ERROR"}

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

                if level_filter != DEFAULT_LEVEL and level != level_filter.upper():
                    continue

                if level not in VALID_LEVELS:
                    ingestion_stats["skipped"]["unknown_level"] += 1
                    if len(diagnostics["unknown_level"]) < MAX_SAMPLES:
                        diagnostics["unknown_level"].append(line)
                    continue
                ingestion_stats["valid_lines"] += 1

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