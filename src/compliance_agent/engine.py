from __future__ import annotations

from dataclasses import dataclass, field

from compliance_agent.models import SecurityRequirement

PRIORITY_WEIGHT = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


@dataclass(slots=True)
class ScoreBreakdown:
    overall_score: float
    risk_level: str
    coverage_score: float
    clarity_score: float
    priority_score: float
    evidence_score: float
    total_requirements: int
    mapped_requirements: int
    flagged_requirements: int
    details: dict[str, float] = field(default_factory=dict)


class ComplianceScoringEngine:
    """Evaluate a policy set using a risk-aware scoring model."""

    def __init__(
        self,
        coverage_weight: float = 0.4,
        clarity_weight: float = 0.25,
        priority_weight: float = 0.2,
        evidence_weight: float = 0.15,
    ) -> None:
        self.coverage_weight = coverage_weight
        self.clarity_weight = clarity_weight
        self.priority_weight = priority_weight
        self.evidence_weight = evidence_weight

    def score_requirements(self, requirements: list[SecurityRequirement]) -> ScoreBreakdown:
        if not requirements:
            return ScoreBreakdown(
                overall_score=0.0,
                risk_level="low",
                coverage_score=0.0,
                clarity_score=0.0,
                priority_score=0.0,
                evidence_score=0.0,
                total_requirements=0,
                mapped_requirements=0,
                flagged_requirements=0,
                details={},
            )

        mapped_requirements = sum(1 for requirement in requirements if requirement.mappings)
        flagged_requirements = sum(
            1
            for requirement in requirements
            if requirement.needs_human_review or requirement.ambiguity_flags
        )
        evidence_count = sum(1 for requirement in requirements if requirement.evidence)

        coverage_score = (mapped_requirements / len(requirements)) * 100.0
        clarity_score = (
            100.0 * (1 - (flagged_requirements / len(requirements)))
            if requirements
            else 100.0
        )
        priority_index = sum(
            PRIORITY_WEIGHT.get(requirement.priority, 0.5) for requirement in requirements
        ) / len(requirements)
        priority_score = priority_index * 100.0
        evidence_score = (evidence_count / len(requirements)) * 100.0

        coverage_risk = 100.0 - coverage_score
        clarity_risk = 100.0 - clarity_score
        evidence_risk = 100.0 - evidence_score
        priority_risk = priority_score

        overall_score = (
            coverage_risk * self.coverage_weight
            + clarity_risk * self.clarity_weight
            + priority_risk * self.priority_weight
            + evidence_risk * self.evidence_weight
        )
        overall_score = round(max(0.0, min(100.0, overall_score)), 2)
        risk_level = self._risk_level(overall_score)

        return ScoreBreakdown(
            overall_score=overall_score,
            risk_level=risk_level,
            coverage_score=round(coverage_score, 2),
            clarity_score=round(clarity_score, 2),
            priority_score=round(priority_score, 2),
            evidence_score=round(evidence_score, 2),
            total_requirements=len(requirements),
            mapped_requirements=mapped_requirements,
            flagged_requirements=flagged_requirements,
            details={
                "coverage": round(coverage_risk, 2),
                "clarity": round(clarity_risk, 2),
                "priority": round(priority_risk, 2),
                "evidence": round(evidence_risk, 2),
            },
        )

    def score_document(self, document: object) -> ScoreBreakdown:
        requirements = getattr(document, "requirements", [])
        return self.score_requirements(requirements)

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
