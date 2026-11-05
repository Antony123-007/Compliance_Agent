from __future__ import annotations

from compliance_agent.engine import ComplianceScoringEngine
from compliance_agent.models import ControlMapping, SecurityRequirement


def _req(
    requirement_id: str,
    priority: str = "medium",
    confidence: float = 0.85,
    mapped: bool = True,
    needs_review: bool = False,
    evidence: list[str] | None = None,
):
    return SecurityRequirement(
        requirement_id=requirement_id,
        title=f"Rule {requirement_id}",
        source_text="Sample statement",
        normalized_statement="Sample statement",
        intent="Protect the environment",
        security_domain="access control",
        action="enforce control",
        priority=priority,
        confidence=confidence,
        ambiguity_flags=[] if not needs_review else ["vague"],
        needs_human_review=needs_review,
        evidence=evidence or ["evidence-1"],
        mappings=[
            ControlMapping(
                framework="NIST CSF 2.0",
                version="2.0",
                control_id="PR.AA-05",
                control_title="Access permissions are limited",
                relation="exact",
                rationale="keyword match",
            )
        ]
        if mapped
        else [],
    )


def test_engine_scores_requirements_and_flags_risk_level():
    engine = ComplianceScoringEngine()
    requirements = [
        _req("REQ-01", priority="high", mapped=True, confidence=0.9),
        _req("REQ-02", priority="critical", mapped=False, confidence=0.7, needs_review=True),
    ]

    result = engine.score_requirements(requirements)

    assert 0 <= result.overall_score <= 100
    assert result.risk_level in ("low", "medium", "high", "critical")
    assert result.coverage_score >= 0
    assert result.clarity_score >= 0
    assert result.priority_score >= 0


def test_engine_applies_higher_weight_to_unmapped_and_ambiguous_requirements():
    engine = ComplianceScoringEngine()
    clean = _req("REQ-01", priority="low", mapped=True, confidence=0.95)
    risky = _req("REQ-02", priority="critical", mapped=False, confidence=0.55, needs_review=True)

    clean_result = engine.score_requirements([clean])
    risky_result = engine.score_requirements([risky])

    assert risky_result.overall_score > clean_result.overall_score
