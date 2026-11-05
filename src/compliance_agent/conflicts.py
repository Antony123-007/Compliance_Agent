from __future__ import annotations

from dataclasses import dataclass

from compliance_agent.models import SecurityRequirement


@dataclass(slots=True)
class ConflictIssue:
    issue_type: str
    requirement_id_a: str
    requirement_id_b: str
    message: str
    severity: str = "warning"


def detect_conflicts(documents: list[object]) -> list[ConflictIssue]:
    issues: list[ConflictIssue] = []
    requirements: list[SecurityRequirement] = []
    for doc in documents:
        requirements.extend(getattr(doc, "requirements", []))

    for index, left in enumerate(requirements):
        for right in requirements[index + 1 :]:
            if not _same_domain(left, right):
                continue
            if _is_contradictory(left, right):
                issues.append(
                    ConflictIssue(
                        issue_type="conflict",
                        requirement_id_a=left.requirement_id,
                        requirement_id_b=right.requirement_id,
                        message=(
                            f"Contradictory statements: '{left.normalized_statement}' "
                            f"vs '{right.normalized_statement}'"
                        ),
                        severity="warning",
                    )
                )
    return issues


def _same_domain(left: SecurityRequirement, right: SecurityRequirement) -> bool:
    return (
        left.security_domain.lower() == right.security_domain.lower()
        or left.action.lower() == right.action.lower()
    )


def _is_contradictory(left: SecurityRequirement, right: SecurityRequirement) -> bool:
    left_text = (left.normalized_statement + " " + left.source_text).lower()
    right_text = (right.normalized_statement + " " + right.source_text).lower()

    shared_terms = set(left_text.split()) & set(right_text.split())
    if not shared_terms:
        return False

    required_patterns = ("must", "required", "shall", "mandatory")
    optional_patterns = ("not required", "may", "optional", "can", "not necessary")

    left_requires = any(pattern in left_text for pattern in required_patterns)
    right_requires = any(pattern in right_text for pattern in required_patterns)
    left_optional = any(pattern in left_text for pattern in optional_patterns)
    right_optional = any(pattern in right_text for pattern in optional_patterns)

    if (left_requires and right_optional) or (right_requires and left_optional):
        return True

    if ("must" in left_text and "not required" in right_text) or (
        "must" in right_text and "not required" in left_text
    ):
        return True

    return False
