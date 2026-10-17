from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from compliance_agent.document_loader import load_text
from compliance_agent.exporters import export_document
from compliance_agent.llm import LLMClient
from compliance_agent.models import ComplianceDocument
from compliance_agent.pipeline import run_baseline, run_pipeline
from compliance_agent.validation import validate_export_pair


@dataclass(slots=True)
class EvaluationMetrics:
    extraction_precision: float
    extraction_recall: float
    mapping_precision: float
    mapping_recall: float
    schema_validity_rate: float
    output_consistency_rate: float
    hallucination_rate: float
    human_review_rate: float
    conflict_detection_recall: float


def evaluate_dataset(
    dataset_path: Path, client: LLMClient, mode: str = "full"
) -> EvaluationMetrics:
    cases = json.loads(dataset_path.read_text(encoding="utf-8"))
    totals = {
        "expected_requirements": 0,
        "actual_requirements": 0,
        "matched_requirements": 0,
        "expected_mappings": 0,
        "actual_mappings": 0,
        "matched_mappings": 0,
        "valid_documents": 0,
        "consistent_documents": 0,
        "hallucinated_requirements": 0,
        "reviewed_requirements": 0,
        "expected_conflicts": 0,
        "detected_conflicts": 0,
    }

    for case in cases:
        input_path = dataset_path.parent / case["input_file"]
        document = (
            run_pipeline(input_path, client)
            if mode == "full"
            else run_baseline(input_path, client)
        )
        _accumulate_case_metrics(case, document, totals)

    actual_requirements = max(totals["actual_requirements"], 1)
    expected_requirements = max(totals["expected_requirements"], 1)
    actual_mappings = max(totals["actual_mappings"], 1)
    expected_mappings = max(totals["expected_mappings"], 1)
    document_count = max(len(cases), 1)

    return EvaluationMetrics(
        extraction_precision=totals["matched_requirements"] / actual_requirements,
        extraction_recall=totals["matched_requirements"] / expected_requirements,
        mapping_precision=totals["matched_mappings"] / actual_mappings,
        mapping_recall=totals["matched_mappings"] / expected_mappings,
        schema_validity_rate=totals["valid_documents"] / document_count,
        output_consistency_rate=totals["consistent_documents"] / document_count,
        hallucination_rate=totals["hallucinated_requirements"] / actual_requirements,
        human_review_rate=totals["reviewed_requirements"] / actual_requirements,
        conflict_detection_recall=totals["detected_conflicts"] / max(totals["expected_conflicts"], 1),
    )


def _accumulate_case_metrics(
    case: dict, document: ComplianceDocument, totals: dict[str, int]
) -> None:
    expected_requirements = {
        item["normalized_statement"].lower() for item in case["expected_requirements"]
    }
    actual_requirements = {
        item.normalized_statement.lower() for item in document.requirements
    }
    totals["expected_requirements"] += len(expected_requirements)
    totals["matched_requirements"] += len(
        expected_requirements.intersection(actual_requirements)
    )
    totals["actual_requirements"] += len(actual_requirements)

    expected_mappings = {
        mapping
        for item in case["expected_requirements"]
        for mapping in item.get("mappings", [])
    }
    actual_mappings = {
        mapping.control_id
        for item in document.requirements
        for mapping in item.mappings
    }
    totals["expected_mappings"] += len(expected_mappings)
    totals["actual_mappings"] += len(actual_mappings)
    totals["matched_mappings"] += len(expected_mappings.intersection(actual_mappings))

    if document.validation_report.valid:
        totals["valid_documents"] += 1

    with TemporaryDirectory() as temp_dir:
        json_path, yaml_path = export_document(document, Path(temp_dir))
        if validate_export_pair(json_path, yaml_path).valid:
            totals["consistent_documents"] += 1

    document_text = load_text(Path(document.source_file)).lower()
    totals["hallucinated_requirements"] += sum(
        1 for item in document.requirements if item.source_text.lower() not in document_text
    )
    totals["reviewed_requirements"] += sum(
        1 for item in document.requirements if item.needs_human_review
    )

    expected_conflicts = case.get("expected_conflicts", [])
    detected_conflicts = [
        issue
        for issue in document.validation_report.issues
        if issue.code == "conflicting_requirement"
    ]
    totals["expected_conflicts"] += len(expected_conflicts)
    totals["detected_conflicts"] += min(len(expected_conflicts), len(detected_conflicts))
