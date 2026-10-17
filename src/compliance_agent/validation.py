from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from compliance_agent.frameworks import catalog_by_key, suggest_mappings
from compliance_agent.models import (
    ComplianceDocument,
    RejectedMapping,
    SecurityRequirement,
    ValidationIssue,
    ValidationReport,
)

VAGUE_TERMS = {
    "adequate",
    "appropriate",
    "reasonable",
    "timely",
    "secure",
    "sensitive",
    "periodic",
    "as needed",
    "where possible",
}

PROMPT_INJECTION_PATTERNS = (
    r"ignore (all|any|previous) instructions",
    r"disregard prompt",
    r"you are chatgpt",
    r"system prompt",
    r"developer message",
)


def normalize_requirement_ids(requirements: list[SecurityRequirement]) -> None:
    for index, requirement in enumerate(requirements, start=1):
        requirement.requirement_id = f"REQ-{index:04d}"


def enrich_and_validate(
    requirements: list[SecurityRequirement], document_text: str | None = None
) -> ValidationReport:
    issues: list[ValidationIssue] = []
    supported_controls = catalog_by_key()
    fingerprints: dict[str, str] = {}

    if document_text:
        issues.extend(_detect_untrusted_document_patterns(document_text))

    for requirement in requirements:
        _apply_ambiguity_heuristics(requirement)
        _validate_required_fields(requirement, issues)
        _validate_traceability(requirement, document_text, issues)
        _validate_and_fix_mappings(requirement, supported_controls, issues)

        fingerprint = _fingerprint(requirement.source_text or requirement.normalized_statement)
        if fingerprint in fingerprints:
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="duplicate_requirement",
                    message=f"Potential duplicate of {fingerprints[fingerprint]}",
                    requirement_id=requirement.requirement_id,
                )
            )
        else:
            fingerprints[fingerprint] = requirement.requirement_id

    issues.extend(_detect_requirement_conflicts(requirements))
    return ValidationReport(
        valid=not any(issue.severity == "error" for issue in issues), issues=issues
    )


def validate_export_pair(json_path: Path, yaml_path: Path) -> ValidationReport:
    issues: list[ValidationIssue] = []
    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    yaml_payload = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

    if json_payload != yaml_payload:
        issues.append(
            ValidationIssue(
                severity="error",
                code="output_mismatch",
                message="JSON and YAML outputs are not equivalent.",
            )
        )
    return ValidationReport(valid=not issues, issues=issues)


def document_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_required_fields(
    requirement: SecurityRequirement, issues: list[ValidationIssue]
) -> None:
    required_fields = {
        "title": requirement.title,
        "source_text": requirement.source_text,
        "normalized_statement": requirement.normalized_statement,
        "intent": requirement.intent,
        "security_domain": requirement.security_domain,
        "action": requirement.action,
    }
    for field_name, value in required_fields.items():
        if not value:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="missing_field",
                    message=f"Missing required field: {field_name}",
                    requirement_id=requirement.requirement_id,
                )
            )


def _validate_traceability(
    requirement: SecurityRequirement,
    document_text: str | None,
    issues: list[ValidationIssue],
) -> None:
    if not document_text or not requirement.source_text:
        return
    if requirement.source_text.lower() not in document_text.lower():
        issues.append(
            ValidationIssue(
                severity="warning",
                code="traceability_gap",
                message="Source text is not present verbatim in the source document.",
                requirement_id=requirement.requirement_id,
            )
        )


def _validate_and_fix_mappings(
    requirement: SecurityRequirement,
    supported_controls: dict[tuple[str, str], object],
    issues: list[ValidationIssue],
) -> None:
    accepted = []
    for mapping in requirement.mappings:
        key = (mapping.framework, mapping.control_id)
        if key not in supported_controls:
            requirement.rejected_mappings.append(
                RejectedMapping(
                    framework=mapping.framework,
                    version=mapping.version,
                    control_id=mapping.control_id,
                    reason="Control is not in the local supported framework catalog.",
                )
            )
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="unsupported_mapping",
                    message=f"Unsupported mapping removed: {mapping.framework} {mapping.control_id}",
                    requirement_id=requirement.requirement_id,
                )
            )
            continue
        accepted.append(mapping)

    requirement.mappings = accepted
    if not requirement.mappings:
        requirement.mappings = suggest_mappings(requirement)


def _apply_ambiguity_heuristics(requirement: SecurityRequirement) -> None:
    lowered = f"{requirement.source_text} {requirement.normalized_statement}".lower()
    for term in VAGUE_TERMS:
        if term in lowered and term not in requirement.ambiguity_flags:
            requirement.ambiguity_flags.append(f"Contains vague term: {term}")
    if requirement.confidence < 0.7:
        requirement.ambiguity_flags.append("Low confidence interpretation")
    if requirement.ambiguity_flags:
        requirement.needs_human_review = True


def _detect_untrusted_document_patterns(document_text: str) -> list[ValidationIssue]:
    lowered = document_text.lower()
    issues: list[ValidationIssue] = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            issues.append(
                ValidationIssue(
                    severity="warning",
                    code="untrusted_input_pattern",
                    message=(
                        "Source document contains prompt-like or instruction-like text "
                        "and should be reviewed carefully."
                    ),
                )
            )
            break
    return issues


def _detect_requirement_conflicts(
    requirements: list[SecurityRequirement],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for index, left in enumerate(requirements):
        for right in requirements[index + 1 :]:
            if not _same_target(left, right):
                continue
            if _is_conflict(left, right):
                left.needs_human_review = True
                right.needs_human_review = True
                if "Potential policy conflict" not in left.ambiguity_flags:
                    left.ambiguity_flags.append("Potential policy conflict")
                if "Potential policy conflict" not in right.ambiguity_flags:
                    right.ambiguity_flags.append("Potential policy conflict")
                issues.append(
                    ValidationIssue(
                        severity="warning",
                        code="conflicting_requirement",
                        message=(
                            f"Potential conflict with {right.requirement_id}: "
                            "contradictory access direction for the same target."
                        ),
                        requirement_id=left.requirement_id,
                    )
                )
    return issues


def _same_target(left: SecurityRequirement, right: SecurityRequirement) -> bool:
    left_resource = (left.resource or "").strip().lower()
    right_resource = (right.resource or "").strip().lower()
    left_domain = left.security_domain.strip().lower()
    right_domain = right.security_domain.strip().lower()

    if left_resource and right_resource:
        return left_resource == right_resource
    return left_domain == right_domain and (left.subject or "").lower() == (
        right.subject or ""
    ).lower()


def _is_conflict(left: SecurityRequirement, right: SecurityRequirement) -> bool:
    left_effect = _classify_effect(left)
    right_effect = _classify_effect(right)
    return {left_effect, right_effect} == {"allow", "deny"}


def _classify_effect(requirement: SecurityRequirement) -> str:
    text = " ".join(
        [
            requirement.action,
            requirement.normalized_statement,
            requirement.source_text,
            " ".join(requirement.conditions),
        ]
    ).lower()

    deny_terms = ("must not", "may not", "shall not", "deny", "prohibit", "blocked", "not access")
    allow_terms = ("may access", "allowed", "authorized", "permitted", "can access")

    if any(term in text for term in deny_terms):
        return "deny"
    if any(term in text for term in allow_terms):
        return "allow"
    return "other"


def _fingerprint(value: str) -> str:
    normalized = " ".join(value.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
