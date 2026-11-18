from __future__ import annotations

import json
import os
import re
from pathlib import Path

from compliance_agent.framework_ingest import build_framework_snapshot
from compliance_agent.models import FrameworkCatalogSnapshot, FrameworkControl, NormalizedControl


def default_catalog_path() -> Path:
    configured = os.getenv("COMPLIANCE_AGENT_CATALOG_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return _repo_root() / "datasets" / "framework_catalog" / "catalog.json"


def build_catalog(input_path: Path, output_path: Path | None = None) -> FrameworkCatalogSnapshot:
    snapshot = build_framework_snapshot(input_path)
    target = output_path or default_catalog_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
    return snapshot


def load_catalog(path: Path | None = None) -> FrameworkCatalogSnapshot | None:
    target = path or default_catalog_path()
    if not target.exists():
        return None
    payload = json.loads(target.read_text(encoding="utf-8"))
    return FrameworkCatalogSnapshot.model_validate(payload)


def load_framework_controls(
    path: Path | None = None,
    fallback: list[FrameworkControl] | None = None,
) -> list[FrameworkControl]:
    snapshot = load_catalog(path)
    base_controls = list(fallback or [])
    if not snapshot or not snapshot.controls:
        return base_controls

    merged: dict[tuple[str, str, str], FrameworkControl] = {
        (control.framework, control.version, control.control_id): control
        for control in base_controls
    }
    for control in snapshot.controls:
        normalized = _to_framework_control(control)
        key = (normalized.framework, normalized.version, normalized.control_id)
        merged[key] = normalized
    return list(merged.values())


def catalog_metadata(path: Path | None = None) -> dict[str, object]:
    target = path or default_catalog_path()
    snapshot = load_catalog(target)
    if not snapshot:
        return {
            "exists": False,
            "path": str(target),
            "built_at": None,
            "control_count": 0,
            "source_files": [],
            "frameworks": {},
        }

    frameworks: dict[str, int] = {}
    for control in snapshot.controls:
        key = f"{control.framework} ({control.version})"
        frameworks[key] = frameworks.get(key, 0) + 1

    return {
        "exists": True,
        "path": str(target),
        "built_at": snapshot.built_at.isoformat(),
        "control_count": len(snapshot.controls),
        "source_files": snapshot.source_files,
        "frameworks": frameworks,
    }


def search_controls(query: str, path: Path | None = None, limit: int = 10) -> list[FrameworkControl]:
    controls = load_framework_controls(path=path)
    if not controls or not query.strip():
        return []

    query_tokens = _tokenize(query)
    ranked: list[tuple[int, FrameworkControl]] = []
    for control in controls:
        blob = " ".join([control.control_id, control.title, control.summary, " ".join(control.tags)])
        tokens = _tokenize(blob)
        score = len(query_tokens.intersection(tokens))
        if score > 0:
            ranked.append((score, control))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [control for _, control in ranked[: max(limit, 1)]]


def _to_framework_control(control: NormalizedControl) -> FrameworkControl:
    summary_parts = [control.description]
    if control.recommendation:
        summary_parts.append(f"Recommendation: {control.recommendation}")
    if control.category:
        summary_parts.append(f"Category: {control.category}")
    summary = " | ".join(summary_parts)

    return FrameworkControl(
        framework=control.framework,
        version=control.version,
        control_id=control.control_id,
        title=control.title,
        summary=summary,
        tags=control.tags,
    )


def _tokenize(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) > 2}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]
