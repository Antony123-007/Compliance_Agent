from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from compliance_agent.document_loader import load_text
from compliance_agent.llm import LLMClient
from compliance_agent.models import (
    ComplianceDocument,
    ExtractionEnvelope,
    SecurityRequirement,
    ValidationIssue,
)
from compliance_agent.validation import (
    document_sha256,
    enrich_and_validate,
    normalize_requirement_ids,
)


def run_pipeline(input_path: Path, client: LLMClient) -> ComplianceDocument:
    text = load_text(input_path)
    source_name = input_path.name
    raw = client.extract(source_name, text)
    requirements = _validate_or_correct(client, raw)
    normalize_requirement_ids(requirements)
    validation_report = enrich_and_validate(requirements, document_text=text)
    return ComplianceDocument(
        source_file=str(input_path),
        source_sha256=document_sha256(input_path),
        model_provider=client.settings.provider_name,
        model_name=client.settings.model,
        requirements=requirements,
        validation_report=validation_report,
    )


def run_baseline(input_path: Path, client: LLMClient) -> ComplianceDocument:
    text = load_text(input_path)
    raw = client.baseline_extract(input_path.name, text)
    requirements = _validate_or_correct(client, raw)
    normalize_requirement_ids(requirements)
    validation_report = enrich_and_validate(requirements, document_text=text)
    return ComplianceDocument(
        source_file=str(input_path),
        source_sha256=document_sha256(input_path),
        model_provider=client.settings.provider_name,
        model_name=f"{client.settings.model} (baseline)",
        requirements=requirements,
        validation_report=validation_report,
    )


def _validate_or_correct(client: LLMClient, raw: dict) -> list[SecurityRequirement]:
    try:
        return ExtractionEnvelope.model_validate(raw).requirements
    except ValidationError as exc:
        corrected = client.correct([error["msg"] for error in exc.errors()], str(raw))
        try:
            return ExtractionEnvelope.model_validate(corrected).requirements
        except ValidationError as corrected_exc:
            messages = "; ".join(error["msg"] for error in corrected_exc.errors())
            raise ValueError(
                f"Model output remained invalid after correction: {messages}"
            ) from corrected_exc


def validation_summary_lines(document: ComplianceDocument) -> list[str]:
    lines = [
        f"Validation status: {'PASS' if document.validation_report.valid else 'FAIL'}"
    ]
    lines.append(f"Requirements extracted: {len(document.requirements)}")

    if not document.validation_report.issues:
        lines.append("No validation issues detected.")
        return lines

    for issue in document.validation_report.issues:
        location = f" ({issue.requirement_id})" if issue.requirement_id else ""
        lines.append(
            f"- {issue.severity.upper()} {issue.code}{location}: {issue.message}"
        )
    return lines
