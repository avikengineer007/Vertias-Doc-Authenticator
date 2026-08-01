"""Unit tests for DocumentReport schema and VerdictAggregator."""

import json
from doc_forensics.report.schema import CheckResult, CheckStatus, DocumentReport
from doc_forensics.report.verdict import VerdictAggregator


def test_verdict_aggregator_authentic():
    res1 = CheckResult(
        module_name="metadata",
        status=CheckStatus.AUTHENTIC,
        score=0.0,
        explanation="Clean EXIF"
    )
    res2 = CheckResult(
        module_name="ela",
        status=CheckStatus.AUTHENTIC,
        score=0.1,
        explanation="Uniform error"
    )

    report = VerdictAggregator.aggregate("sample.jpg", [res1, res2])
    assert report.verdict == CheckStatus.AUTHENTIC
    assert report.overall_risk_score < 0.2
    assert "metadata" in report.checks
    assert "ela" in report.checks


def test_verdict_aggregator_fail_closed_tampering():
    res1 = CheckResult(
        module_name="metadata",
        status=CheckStatus.AUTHENTIC,
        score=0.0,
        explanation="Clean EXIF"
    )
    res2 = CheckResult(
        module_name="ela",
        status=CheckStatus.SUSPECTED_TAMPERING,
        score=0.85,
        explanation="High ELA variance"
    )

    report = VerdictAggregator.aggregate("sample.jpg", [res1, res2])
    assert report.verdict == CheckStatus.SUSPECTED_TAMPERING
    assert report.overall_risk_score >= 0.6
    assert "SUSPECTED TAMPERING" in report.summary


def test_document_report_json_serialization():
    res = CheckResult(
        module_name="noise_analysis",
        status=CheckStatus.INCONCLUSIVE,
        score=0.4,
        explanation="Noise variation"
    )
    report = VerdictAggregator.aggregate("sample.jpg", [res])
    json_str = report.to_json()
    data = json.loads(json_str)

    assert data["image_path"] == "sample.jpg"
    assert data["verdict"] == "INCONCLUSIVE"
    assert "noise_analysis" in data["checks"]
