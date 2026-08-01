"""Report models, schema definitions, and verdict aggregation logic."""

from doc_forensics.report.schema import CheckStatus, Severity, CheckResult, DocumentReport
from doc_forensics.report.verdict import VerdictAggregator

__all__ = ["CheckStatus", "Severity", "CheckResult", "DocumentReport", "VerdictAggregator"]
