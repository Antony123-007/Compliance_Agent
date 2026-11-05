from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from compliance_agent.document_loader import load_text
from compliance_agent.models import ComplianceDocument, SecurityRequirement, ValidationReport

_SUPPORTED_SUFFIXES = {".txt", ".pdf", ".docx", ".doc"}


def ingest_policy_repository(path: Path) -> list[ComplianceDocument]:
    """Collect policy documents from folder and normalize them into compliance documents."""
    files = _discover_files(path)
    documents: list[ComplianceDocument] = []

    for index, file_path in enumerate(files, start=1):
        text = load_text(file_path)
        snippet = text[:2000]
        requirement = SecurityRequirement(
            requirement_id=f"REQ-{index:04d}",
            title=_title_from_path(file_path),
            source_text=snippet,
            normalized_statement=snippet,
            intent="Extract policy obligation from repository input.",
            security_domain=_infer_domain(file_path, text),
            action="comply with policy",
            priority="medium",
            confidence=0.8,
            ambiguity_flags=[],
            needs_human_review=False,
            evidence=[f"Repository ingest: {file_path.name}"],
            mappings=[],
        )
        documents.append(
            ComplianceDocument(
                source_file=str(file_path),
                source_sha256=_sha256(file_path),
                extracted_at=datetime.now(timezone.utc),
                model_provider="repository",
                model_name="local-ingestion",
                requirements=[requirement],
                validation_report=ValidationReport(valid=True, issues=[]),
            )
        )
    return documents


def _discover_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in _SUPPORTED_SUFFIXES else []
    if not path.exists():
        return []
    return sorted(
        [
            candidate
            for candidate in path.rglob("*")
            if candidate.is_file() and candidate.suffix.lower() in _SUPPORTED_SUFFIXES
        ]
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _title_from_path(path: Path) -> str:
    return path.stem.replace("_", " ").replace("-", " ").title()


def _infer_domain(path: Path, text: str) -> str:
    lowered = (path.stem + " " + text).lower()
    if any(term in lowered for term in ("firewall", "network", "port", "vpn", "segmentation")):
        return "network security"
    if any(term in lowered for term in ("access", "identity", "authentication", "account")):
        return "access control"
    if any(term in lowered for term in ("backup", "recovery", "incident", "response")):
        return "resilience"
    return "general compliance"
