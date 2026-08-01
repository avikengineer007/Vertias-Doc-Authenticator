"""Aggregates individual forensic check results into a structured DocumentReport."""

from typing import List, Dict, Any
import numpy as np

from doc_forensics.report.schema import CheckResult, CheckStatus, DocumentReport


class VerdictAggregator:
    """Aggregates forensic check outputs using fail-closed conservative logic."""

    @staticmethod
    def aggregate(
        image_path: str,
        results: List[CheckResult],
        metadata_summary: Dict[str, Any] = None
    ) -> DocumentReport:
        """
        Aggregate a list of module CheckResults into a final DocumentReport.
        
        Logic rules (Fail-closed & Conservative):
        1. If ANY module reports SUSPECTED_TAMPERING with score >= 0.6, overall verdict is SUSPECTED_TAMPERING.
        2. If NO module reports SUSPECTED_TAMPERING, but at least 2 checks are INCONCLUSIVE or have elevated scores (>0.4), overall verdict is INCONCLUSIVE.
        3. If all checks report AUTHENTIC and no flags fired, overall verdict is AUTHENTIC.
        4. Overall risk score is weighted max of module scores.
        """
        if metadata_summary is None:
            metadata_summary = {}

        checks_dict: Dict[str, CheckResult] = {res.module_name: res for res in results}

        if not results:
            return DocumentReport(
                image_path=image_path,
                verdict=CheckStatus.INCONCLUSIVE,
                overall_risk_score=0.5,
                checks={},
                summary="No forensic checks were executed.",
                metadata_summary=metadata_summary
            )

        tampered_checks = [r for r in results if r.status == CheckStatus.SUSPECTED_TAMPERING]
        inconclusive_checks = [r for r in results if r.status == CheckStatus.INCONCLUSIVE]
        authentic_checks = [r for r in results if r.status == CheckStatus.AUTHENTIC]

        # Calculate max and mean risk score
        scores = [r.score for r in results]
        max_score = max(scores) if scores else 0.0
        mean_score = float(np.mean(scores)) if scores else 0.0
        
        # Aggregated risk score heavily weights the highest severity check
        overall_risk = float(np.clip(0.7 * max_score + 0.3 * mean_score, 0.0, 1.0))

        summary_lines = []
        if tampered_checks:
            overall_verdict = CheckStatus.SUSPECTED_TAMPERING
            summary_lines.append(
                f"SUSPECTED TAMPERING detected: {len(tampered_checks)} check(s) flagged anomalies "
                f"({', '.join([c.module_name for c in tampered_checks])})."
            )
            for c in tampered_checks:
                summary_lines.append(f" - [{c.module_name}]: {c.explanation}")
        elif len(inconclusive_checks) >= 2 or (inconclusive_checks and max_score > 0.4):
            overall_verdict = CheckStatus.INCONCLUSIVE
            summary_lines.append(
                f"INCONCLUSIVE verdict: {len(inconclusive_checks)} check(s) had insufficient evidence or partial flags "
                f"({', '.join([c.module_name for c in inconclusive_checks])})."
            )
            for c in inconclusive_checks:
                summary_lines.append(f" - [{c.module_name}]: {c.explanation}")
        elif inconclusive_checks:
            overall_verdict = CheckStatus.INCONCLUSIVE
            summary_lines.append(
                f"INCONCLUSIVE verdict due to inconclusive check: {inconclusive_checks[0].module_name}."
            )
            summary_lines.append(f" - [{inconclusive_checks[0].module_name}]: {inconclusive_checks[0].explanation}")
        else:
            overall_verdict = CheckStatus.AUTHENTIC
            summary_lines.append(
                f"AUTHENTIC verdict: All {len(authentic_checks)} executed checks passed with no detected tampering."
            )

        summary_text = "\n".join(summary_lines)

        return DocumentReport(
            image_path=image_path,
            verdict=overall_verdict,
            overall_risk_score=overall_risk,
            checks=checks_dict,
            summary=summary_text,
            metadata_summary=metadata_summary
        )
