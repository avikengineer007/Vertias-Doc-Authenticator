"""Report data model definitions using Pydantic for structured JSON schema."""

from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CheckStatus(str, Enum):
    AUTHENTIC = "AUTHENTIC"
    SUSPECTED_TAMPERING = "SUSPECTED_TAMPERING"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CheckResult(BaseModel):
    """Structured result from an individual forensic check module."""
    module_name: str = Field(..., description="Unique name of the forensic check module")
    status: CheckStatus = Field(..., description="Verdict status of this check")
    score: float = Field(..., ge=0.0, le=1.0, description="Risk or error score (0.0 = clean, 1.0 = highly tampered)")
    explanation: str = Field(..., description="Human-readable explanation of why this verdict was reached")
    details: Dict[str, Any] = Field(default_factory=dict, description="Raw metrics, tags, or feature points")
    execution_time_ms: float = Field(0.0, description="Module execution duration in milliseconds")
    heatmap_path: Optional[str] = Field(None, description="Path to generated visual heatmap overlay if available")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class DocumentReport(BaseModel):
    """Comprehensive aggregated document forensic report."""
    image_path: str = Field(..., description="Absolute or relative path of the analyzed document")
    scan_timestamp: str = Field(default_factory=lambda: datetime.now().isoformat(), description="ISO timestamp of scan")
    verdict: CheckStatus = Field(..., description="Overall aggregated verdict (fail-closed conservative default)")
    overall_risk_score: float = Field(..., ge=0.0, le=1.0, description="Aggregated risk score")
    checks: Dict[str, CheckResult] = Field(default_factory=dict, description="Dictionary of individual check results")
    summary: str = Field(..., description="Executive summary explaining all fired checks and flags")
    metadata_summary: Dict[str, Any] = Field(default_factory=dict, description="Key extracted document metadata")

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
