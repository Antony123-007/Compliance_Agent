from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from compliance_agent.exporters import export_document
from compliance_agent.models import ComplianceDocument, SecurityRequirement, ValidationReport
from compliance_agent.validation import validate_export_pair


def test_json_and_yaml_exports_match(tmp_path: Path) -> None:
    document = ComplianceDocument(
        source_file="policy.txt",
        source_sha256="abc",
        extracted_at=datetime.now(timezone.utc),
        model_provider="test",
        model_name="fake",
        requirements=[
            SecurityRequirement(
                requirement_id="REQ-0001",
                title="Restrict admin access",
                source_text="Only authorized administrators may access management interfaces.",
                normalized_statement="Restrict management interface access to authorized administrators only.",
                intent="Reduce unauthorized privileged access.",
                security_domain="Access Control",
                action="access",
                confidence=0.9,
            )
        ],
        validation_report=ValidationReport(valid=True, issues=[]),
    )

    json_path, yaml_path = export_document(document, tmp_path)
    report = validate_export_pair(json_path, yaml_path)

    assert report.valid is True
