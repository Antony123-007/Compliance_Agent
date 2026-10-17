from __future__ import annotations

import json
from pathlib import Path

import yaml

from compliance_agent.models import ComplianceDocument


def export_document(document: ComplianceDocument, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = document.model_dump(mode="json")

    json_path = output_dir / "requirements.json"
    yaml_path = output_dir / "requirements.yaml"

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    yaml_path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )
    return json_path, yaml_path
