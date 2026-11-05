from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from compliance_agent.config import (
    configured_output_root,
    default_api_key_env,
    default_base_url,
    default_model,
    load_environment,
)
from compliance_agent.conflicts import detect_conflicts
from compliance_agent.coverage import build_coverage_matrix
from compliance_agent.engine import ComplianceScoringEngine
from compliance_agent.exporters import export_document
from compliance_agent.llm import LLMClient, LLMRequestError, LLMResponseError, LLMSettings
from compliance_agent.pipeline import run_pipeline, validation_summary_lines
from compliance_agent.reporting import generate_report_bundle
from compliance_agent.repository import ingest_policy_repository
from compliance_agent.review import create_review_queue
from compliance_agent.validation import validate_export_pair

st.set_page_config(
    page_title="Compliance Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)


def _default_output_dir(input_path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = configured_output_root() or (
        Path.home() / "Documents" / "ComplianceAgentOutputs"
    )
    return output_root / f"{input_path.stem}-{timestamp}"


def _resolve_input_file(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser().resolve()
    if candidate.is_file():
        return candidate
    if candidate.is_dir():
        for pattern in ("*.txt", "*.md", "*.csv", "*.json", "*.yaml", "*.yml"):
            matches = sorted(candidate.glob(pattern))
            if matches:
                return matches[0]
        raise FileNotFoundError(
            f"No supported security control file was found in: {candidate}"
        )
    raise FileNotFoundError(f"Security controls path not found: {candidate}")


def _safe_repo_docs(path_value: str) -> list[object]:
    repo_path = Path(path_value).expanduser().resolve()
    if not repo_path.exists():
        st.warning(f"Directory not found: {repo_path}")
        return []
    return ingest_policy_repository(repo_path)


def _score_documents(documents: list[object]) -> dict[str, float | str | int]:
    all_requirements = [
        requirement
        for document in documents
        for requirement in getattr(document, "requirements", [])
    ]
    engine = ComplianceScoringEngine()
    result = engine.score_requirements(all_requirements)
    return {
        "overall_score": result.overall_score,
        "risk_level": result.risk_level,
        "coverage_gap": max(0.0, 100.0 - result.coverage_score),
        "clarity_gap": max(0.0, 100.0 - result.clarity_score),
        "total_requirements": len(all_requirements),
    }


def _requirements_table(requirements) -> pd.DataFrame:
    rows = []
    for requirement in requirements:
        status_text, status_icon = _requirement_status(
            requirement.confidence,
            requirement.ambiguity_flags,
            requirement.needs_human_review,
        )
        rows.append(
            {
                "ID": requirement.requirement_id,
                "Priority": requirement.priority,
                "Confidence": f"{requirement.confidence:.3f}",
                "Maps": len(requirement.mappings),
                "Review": "YES" if requirement.needs_human_review else "NO",
                "Status": f"{status_icon} {status_text}",
                "Domain": requirement.security_domain,
                "Summary": requirement.normalized_statement or requirement.title,
            }
        )
    return pd.DataFrame(rows)


def _requirement_status(
    confidence: float, ambiguity_flags: list[str], needs_review: bool
) -> tuple[str, str]:
    if needs_review or ambiguity_flags or confidence < 0.75:
        return ("Review", "⚠️")
    if confidence >= 0.9:
        return ("Strong", "✅")
    return ("Moderate", "ℹ️")


def main() -> None:
    load_environment()

    st.title("Compliance Intelligence Dashboard")
    st.caption(
        "Security controls analysis, validation, scoring, coverage, conflicts, "
        "review queue, and generated reports"
    )

    with st.sidebar:
        st.header("Input")
        input_path_value = st.text_input(
            "Security controls directory path", value="datasets/evaluation/policies"
        )
        run_clicked = st.button("Run analysis")

    if not run_clicked and not input_path_value.strip():
        st.info(
            "Enter the directory path for the security controls file to start the analysis."
        )
        return

    try:
        input_path = _resolve_input_file(input_path_value)
    except FileNotFoundError as exc:
        st.warning(str(exc))
        return

    if run_clicked:
        try:
            output_dir = _default_output_dir(input_path)
            settings = LLMSettings(
                model=default_model(),
                api_key_env=default_api_key_env(),
                base_url=default_base_url(),
            )
            client = LLMClient(settings)
            document = run_pipeline(input_path, client)
            json_path, yaml_path = export_document(document, output_dir)
            export_report = validate_export_pair(json_path, yaml_path)
            score = ComplianceScoringEngine().score_document(document)

            st.subheader("Analysis output")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Risk score", f"{score.overall_score:.2f}/100")
            col2.metric("Risk level", score.risk_level.upper())
            col3.metric("Requirements", len(document.requirements))
            col4.metric(
                "Validation", "PASS" if document.validation_report.valid else "CHECK"
            )

            st.write("Input file:")
            st.code(str(input_path))
            st.write("Generated files:")
            st.code(f"JSON: {json_path}\nYAML: {yaml_path}\nOutput dir: {output_dir}")

            st.write("Validation summary:")
            for line in validation_summary_lines(document):
                st.write(line)

            st.write("Requirements table")
            st.dataframe(
                _requirements_table(document.requirements),
                use_container_width=False,
                width=1500,
                hide_index=True,
            )

            st.write("Export validation issues")
            if export_report.issues:
                for issue in export_report.issues:
                    st.warning(f"{issue.severity.upper()} {issue.code}: {issue.message}")
            else:
                st.success("Export consistency: OK")

            repo_docs = [document]
            coverage_rows = build_coverage_matrix(repo_docs)
            conflicts = detect_conflicts(repo_docs)
            review_items = create_review_queue(document.requirements)

            tab1, tab2, tab3, tab4, tab5 = st.tabs(
                ["1. Analysis", "2. Coverage", "3. Conflicts", "4. Review Queue", "5. Reports"]
            )

            with tab1:
                st.dataframe(
                    _requirements_table(document.requirements),
                    use_container_width=False,
                    width=1500,
                    hide_index=True,
                )

            with tab2:
                st.dataframe(pd.DataFrame(coverage_rows), use_container_width=True)

            with tab3:
                if conflicts:
                    st.dataframe(
                        pd.DataFrame(
                            [
                                {
                                    "requirement_id_a": issue.requirement_id_a,
                                    "requirement_id_b": issue.requirement_id_b,
                                    "severity": issue.severity,
                                    "message": issue.message,
                                }
                                for issue in conflicts
                            ]
                        ),
                        use_container_width=True,
                    )
                else:
                    st.success("No policy conflicts detected.")

            with tab4:
                if review_items:
                    st.dataframe(
                        pd.DataFrame(
                            [
                                {
                                    "requirement_id": item.requirement_id,
                                    "status": item.status,
                                    "reviewer": item.reviewer or "unassigned",
                                    "notes": item.notes,
                                }
                                for item in review_items
                            ]
                        ),
                        use_container_width=True,
                    )
                else:
                    st.success("No items require human review.")

            with tab5:
                report_bundle = generate_report_bundle(repo_docs, output_dir / "reports")
                st.write("Generated artifacts:")
                st.code(
                    f"- CSV: {output_dir / 'reports' / report_bundle.summary_name}\n"
                    f"- Excel: {output_dir / 'reports' / report_bundle.excel_name}\n"
                    f"- PDF: {output_dir / 'reports' / report_bundle.pdf_name}"
                )
                with open(
                    output_dir / "reports" / report_bundle.summary_name, "rb"
                ) as csv_file:
                    st.download_button(
                        "Download summary CSV",
                        csv_file,
                        file_name=report_bundle.summary_name,
                    )
            return

        except (LLMRequestError, LLMResponseError, ValueError, RuntimeError) as exc:
            st.error(f"Analysis failed: {exc}")
            return

    st.info("Use the sidebar to provide the security controls directory path and click 'Run analysis'.")


if __name__ == "__main__":
    main()
