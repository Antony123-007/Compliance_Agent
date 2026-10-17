from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Priority = Literal["low", "medium", "high", "critical"]
MappingRelation = Literal["exact", "partial", "related"]
IssueSeverity = Literal["info", "warning", "error"]


class RejectedMapping(BaseModel):
    framework: str
    version: str | None = None
    control_id: str
    reason: str


class ControlMapping(BaseModel):
    framework: str
    version: str
    control_id: str
    control_title: str
    relation: MappingRelation
    rationale: str


class SecurityRequirement(BaseModel):
    requirement_id: str
    title: str
    source_text: str
    normalized_statement: str
    intent: str
    security_domain: str
    subject: str | None = None
    action: str
    resource: str | None = None
    conditions: list[str] = Field(default_factory=list)
    exceptions: list[str] = Field(default_factory=list)
    priority: Priority = "medium"
    confidence: float = 0.0
    ambiguity_flags: list[str] = Field(default_factory=list)
    needs_human_review: bool = False
    evidence: list[str] = Field(default_factory=list)
    mappings: list[ControlMapping] = Field(default_factory=list)
    rejected_mappings: list[RejectedMapping] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return round(value, 3)


class ValidationIssue(BaseModel):
    severity: IssueSeverity
    code: str
    message: str
    requirement_id: str | None = None


class ValidationReport(BaseModel):
    valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)


class ComplianceDocument(BaseModel):
    source_file: str
    source_sha256: str
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_provider: str
    model_name: str
    requirements: list[SecurityRequirement]
    validation_report: ValidationReport


class FrameworkControl(BaseModel):
    framework: str
    version: str
    control_id: str
    title: str
    summary: str
    tags: list[str]


class ExtractionEnvelope(BaseModel):
    requirements: list[SecurityRequirement]
