from __future__ import annotations

from dataclasses import dataclass

from compliance_agent.frameworks import FRAMEWORK_CATALOG


@dataclass(slots=True)
class CoverageRow:
    framework: str
    version: str
    total_controls: int
    covered: int
    coverage_rate: float
    missing_controls: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "version": self.version,
            "total_controls": self.total_controls,
            "covered": self.covered,
            "coverage_rate": round(self.coverage_rate, 3),
            "missing_controls": self.missing_controls,
        }


def build_coverage_matrix(documents: list[object]) -> list[dict[str, object]]:
    """Build a framework coverage table for all extracted requirements."""
    coverage_by_framework: dict[tuple[str, str], set[str]] = {}
    for document in documents:
        for requirement in getattr(document, "requirements", []):
            for mapping in requirement.mappings:
                key = (mapping.framework, mapping.version)
                coverage_by_framework.setdefault(key, set()).add(mapping.control_id)

    rows: list[CoverageRow] = []
    for framework in set(item.framework for item in FRAMEWORK_CATALOG):
        for version in sorted(
            {item.version for item in FRAMEWORK_CATALOG if item.framework == framework}
        ):
            controls = [
                item
                for item in FRAMEWORK_CATALOG
                if item.framework == framework and item.version == version
            ]
            key = (framework, version)
            covered_ids = coverage_by_framework.get(key, set())
            missing_ids = [
                item.control_id for item in controls if item.control_id not in covered_ids
            ]
            total_controls = len(controls)
            coverage_rate = (
                (len(covered_ids) / total_controls) if total_controls else 0.0
            )
            rows.append(
                CoverageRow(
                    framework=framework,
                    version=version,
                    total_controls=total_controls,
                    covered=len(covered_ids),
                    coverage_rate=coverage_rate,
                    missing_controls=missing_ids,
                )
            )
    return [row.as_dict() for row in rows]
