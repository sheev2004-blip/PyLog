from dataclasses import dataclass

@dataclass
class IngestionStats:
    total_lines: int
    valid_lines: int
    valid_ratio: float
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