"""doc-forensics: DocumentID Tampering Detection Library."""

from doc_forensics.scanner import ForensicScanner
from doc_forensics.report.schema import CheckStatus, Severity, CheckResult, DocumentReport
from doc_forensics.core.metadata import analyze_metadata
from doc_forensics.core.ela import analyze_ela
from doc_forensics.core.copy_move import analyze_copy_move
from doc_forensics.core.ocr_consistency import analyze_ocr_consistency
from doc_forensics.core.noise_analysis import analyze_noise

__version__ = "0.1.0"

__all__ = [
    "ForensicScanner",
    "CheckStatus",
    "Severity",
    "CheckResult",
    "DocumentReport",
    "analyze_metadata",
    "analyze_ela",
    "analyze_copy_move",
    "analyze_ocr_consistency",
    "analyze_noise",
]
