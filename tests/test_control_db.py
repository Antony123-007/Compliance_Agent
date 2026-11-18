from __future__ import annotations

import json
from pathlib import Path

from compliance_agent.control_db import build_catalog, load_framework_controls, search_controls
from compliance_agent.frameworks import catalog_by_key


def test_build_catalog_extracts_controls_from_text(tmp_path: Path) -> None:
    source_dir = tmp_path / "framework_sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "nist_sample.txt").write_text(
        "NIST CSF 2.0\n"
        "PR.AA-99 Ensure privileged identities are approved before access.\n",
        encoding="utf-8",
    )
    (source_dir / "cis_sample.txt").write_text(
        "CIS Controls v8.1\n"
        "CIS Control 5.2 Ensure account lifecycle is managed.\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "catalog.json"

    snapshot = build_catalog(source_dir, output_path)

    assert output_path.exists()
    ids = {control.control_id for control in snapshot.controls}
    assert "PR.AA-99" in ids
    assert "CIS 5.2" in ids


def test_snapshot_is_used_by_framework_mapping(monkeypatch, tmp_path: Path) -> None:
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        json.dumps(
            {
                "built_at": "2026-01-01T00:00:00+00:00",
                "source_files": ["sample.txt"],
                "controls": [
                    {
                        "framework": "NIST CSF 2.0",
                        "version": "2.0",
                        "control_id": "PR.AA-77",
                        "title": "Custom snapshot control",
                        "description": "Control from snapshot",
                        "category": "Access Control",
                        "recommendation": "Apply access approval workflow",
                        "source": "sample.txt",
                        "tags": ["access", "approval"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("COMPLIANCE_AGENT_CATALOG_PATH", str(catalog_path))

    controls = load_framework_controls(fallback=[])
    assert len(controls) == 1
    assert controls[0].control_id == "PR.AA-77"

    by_key = catalog_by_key()
    assert ("NIST CSF 2.0", "PR.AA-77") in by_key

    results = search_controls("approval workflow")
    assert results
    assert results[0].control_id == "PR.AA-77"
