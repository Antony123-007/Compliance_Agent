from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from compliance_agent.document_loader import load_text
from compliance_agent.models import FrameworkCatalogSnapshot, NormalizedControl

SUPPORTED_SUFFIXES = (".txt", ".md", ".pdf", ".docx", ".doc", ".json", ".csv")

_NIST_CONTROL_PATTERN = re.compile(r"\b([A-Z]{2}\.[A-Z]{2}-\d{2})\b")
_NIST_53_PATTERN = re.compile(r"\b([A-Z]{2}-\d{1,3}(?:\(\d+\))?)\b")
_CIS_CONTROL_PATTERN = re.compile(r"\b(?:CIS\s*)?(?:Control\s*)?(\d{1,2}(?:\.\d+)?)\b", re.IGNORECASE)

_STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "must",
    "shall",
    "should",
    "control",
    "controls",
    "benchmark",
    "framework",
    "security",
}


def discover_framework_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_SUFFIXES else []
    if not path.exists():
        return []
    return sorted(
        [
            candidate
            for candidate in path.rglob("*")
            if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES
        ]
    )


def build_framework_snapshot(path: Path) -> FrameworkCatalogSnapshot:
    source_files: list[str] = []
    controls: list[NormalizedControl] = []

    for file_path in discover_framework_files(path):
        extracted = extract_controls_from_file(file_path)
        if not extracted:
            continue
        source_files.append(str(file_path))
        controls.extend(extracted)

    deduped = _deduplicate_controls(controls)
    return FrameworkCatalogSnapshot(source_files=source_files, controls=deduped)


def extract_controls_from_file(path: Path) -> list[NormalizedControl]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _extract_from_json(path)
    if suffix == ".csv":
        return _extract_from_csv(path)
    return _extract_from_text(path)


def _extract_from_json(path: Path) -> list[NormalizedControl]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload if isinstance(payload, list) else payload.get("controls", [])
    controls: list[NormalizedControl] = []
    for item in items:
        control = _control_from_dict(item, path)
        if control:
            controls.append(control)
    return controls


def _extract_from_csv(path: Path) -> list[NormalizedControl]:
    controls: list[NormalizedControl] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            control = _control_from_dict(row, path)
            if control:
                controls.append(control)
    return controls


def _extract_from_text(path: Path) -> list[NormalizedControl]:
    text = load_text(path)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    hint = f"{path.name}\n{text[:4000]}".lower()
    include_nist = "nist" in hint or "csf" in hint or "800-53" in hint
    include_cis = "cis" in hint or "benchmark" in hint

    controls: list[NormalizedControl] = []
    if include_nist:
        controls.extend(_extract_nist_controls(lines, path, hint))
    if include_cis:
        controls.extend(_extract_cis_controls(lines, path))

    # Fall back to best-effort extraction if document hints are weak.
    if not controls:
        controls.extend(_extract_nist_controls(lines, path, hint))
        controls.extend(_extract_cis_controls(lines, path))
    return controls


def _extract_nist_controls(lines: list[str], path: Path, hint: str) -> list[NormalizedControl]:
    controls: list[NormalizedControl] = []
    framework_name = "NIST SP 800-53" if "800-53" in hint else "NIST CSF 2.0"
    framework_version = "Rev 5" if framework_name == "NIST SP 800-53" else "2.0"

    for line in lines:
        control_id = _first_match(line, (_NIST_CONTROL_PATTERN, _NIST_53_PATTERN))
        if not control_id:
            continue
        description = line.strip()
        controls.append(
            NormalizedControl(
                framework=framework_name,
                version=framework_version,
                control_id=control_id,
                title=_truncate(line, 200),
                description=_truncate(description, 1000),
                category=_infer_category(line),
                recommendation=_infer_recommendation(line),
                source=path.name,
                tags=_derive_tags(line),
            )
        )
    return controls


def _extract_cis_controls(lines: list[str], path: Path) -> list[NormalizedControl]:
    controls: list[NormalizedControl] = []
    for line in lines:
        if "cis" not in line.lower() and "control" not in line.lower() and "benchmark" not in path.name.lower():
            continue
        match = _CIS_CONTROL_PATTERN.search(line)
        if not match:
            continue
        suffix = match.group(1)
        control_id = f"CIS {suffix}"
        controls.append(
            NormalizedControl(
                framework="CIS Controls",
                version="8.1",
                control_id=control_id,
                title=_truncate(line, 200),
                description=_truncate(line, 1000),
                category=_infer_category(line),
                recommendation=_infer_recommendation(line),
                source=path.name,
                tags=_derive_tags(line),
            )
        )
    return controls


def _control_from_dict(item: dict, path: Path) -> NormalizedControl | None:
    framework = str(item.get("framework", "")).strip()
    version = str(item.get("version", "")).strip()
    control_id = str(item.get("control_id", "")).strip()
    title = str(item.get("title", "")).strip()
    description = str(item.get("description", item.get("summary", ""))).strip()
    category = str(item.get("category", "")).strip() or None
    recommendation = str(item.get("recommendation", "")).strip() or None
    source = str(item.get("source", path.name)).strip()

    if not (framework and version and control_id and title):
        return None

    tags_raw = item.get("tags", [])
    if isinstance(tags_raw, list):
        tags = [str(tag).strip() for tag in tags_raw if str(tag).strip()]
    else:
        tags = [segment.strip() for segment in str(tags_raw).split(",") if segment.strip()]
    if not tags:
        tags = _derive_tags(" ".join([title, description, recommendation or ""]))

    return NormalizedControl(
        framework=framework,
        version=version,
        control_id=control_id,
        title=title,
        description=description or title,
        category=category,
        recommendation=recommendation,
        source=source,
        tags=tags,
    )


def _deduplicate_controls(controls: list[NormalizedControl]) -> list[NormalizedControl]:
    deduped: dict[tuple[str, str, str], NormalizedControl] = {}
    for control in controls:
        key = (control.framework, control.version, control.control_id)
        if key not in deduped:
            deduped[key] = control
            continue
        existing = deduped[key]
        if len(control.description) > len(existing.description):
            deduped[key] = control
    return sorted(deduped.values(), key=lambda item: (item.framework, item.version, item.control_id))


def _first_match(line: str, patterns: tuple[re.Pattern[str], ...]) -> str | None:
    for pattern in patterns:
        match = pattern.search(line)
        if match:
            return match.group(1).upper()
    return None


def _derive_tags(text: str, limit: int = 8) -> list[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    tags: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if len(token) < 4 or token in _STOP_WORDS or token in seen:
            continue
        tags.append(token)
        seen.add(token)
        if len(tags) > limit:
            break
    return tags


def _infer_category(text: str) -> str:
    lowered = text.lower()
    if any(term in lowered for term in ("access", "identity", "authentication", "account")):
        return "Access Control"
    if any(term in lowered for term in ("network", "firewall", "traffic", "segmentation")):
        return "Network Security"
    if any(term in lowered for term in ("log", "audit", "monitor", "event")):
        return "Monitoring and Logging"
    if any(term in lowered for term in ("backup", "recovery", "incident", "response")):
        return "Resilience and Response"
    return "General Compliance"


def _infer_recommendation(text: str) -> str:
    lowered = text.lower()
    if "must" in lowered or "shall" in lowered:
        return text.strip()
    return f"Implement control intent: {text.strip()}"


def _truncate(text: str, limit: int) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."
