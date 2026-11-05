from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from compliance_agent.coverage import build_coverage_matrix
from compliance_agent.engine import ComplianceScoringEngine

try:
    from openpyxl import Workbook
except ImportError:  # pragma: no cover
    Workbook = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
except ImportError:  # pragma: no cover
    letter = None
    getSampleStyleSheet = None
    Paragraph = None
    SimpleDocTemplate = None
    Spacer = None


@dataclass(slots=True)
class ReportBundle:
    excel_name: str
    pdf_name: str
    summary_name: str


def generate_report_bundle(
    documents: list[object],
    output_dir: str | Path,
    title: str = "Compliance Intelligence Report",
) -> ReportBundle:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    rows = []
    engine = ComplianceScoringEngine()
    for document in documents:
        requirements = list(getattr(document, "requirements", []))
        score = engine.score_requirements(requirements)
        rows.append(
            {
                "document": getattr(document, "source_file", "unknown"),
                "requirements": len(requirements),
                "risk_score": score.overall_score,
                "risk_level": score.risk_level,
            }
        )

    summary_name = "compliance_summary.csv"
    summary_path = output_path / summary_name
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write("document, requirements, risk_score, risk_level\n")
        for row in rows:
            handle.write(
                f"{row['document']}, {row['requirements']}, {row['risk_score']}, {row['risk_level']}\n"
            )

    excel_name = "compliance_matrix.xlsx"
    if Workbook is not None:
        workbook = Workbook()
        summary_sheet = workbook.active
        summary_sheet.title = "Summary"
        summary_sheet.append(["document", "requirements", "risk_score", "risk_level"])
        for row in rows:
            summary_sheet.append(
                [row["document"], row["requirements"], row["risk_score"], row["risk_level"]]
            )

        coverage_sheet = workbook.create_sheet("Framework Coverage")
        coverage_sheet.append(
            [
                "framework",
                "version",
                "total_controls",
                "covered",
                "coverage_rate",
                "missing_controls",
            ]
        )
        for row in build_coverage_matrix(documents):
            coverage_sheet.append(
                [
                    row["framework"],
                    row["version"],
                    row["total_controls"],
                    row["covered"],
                    row["coverage_rate"],
                    "; ".join(row["missing_controls"]),
                ]
            )
        workbook.save(output_path / excel_name)

    pdf_name = "compliance_report.pdf"
    if SimpleDocTemplate is not None and Paragraph is not None:
        doc = SimpleDocTemplate(str(output_path / pdf_name), pagesize=letter)
        styles = getSampleStyleSheet()
        story = [Paragraph(title, styles["Title"]), Spacer(1, 12)]
        for row in rows:
            story.append(
                Paragraph(
                    f"Document: {row['document']} | Requirements: {row['requirements']} | "
                    f"Risk score: {row['risk_score']:.2f} | Risk: {row['risk_level']}",
                    styles["BodyText"],
                )
            )
        doc.build(story)

    return ReportBundle(excel_name=excel_name, pdf_name=pdf_name, summary_name=summary_name)
