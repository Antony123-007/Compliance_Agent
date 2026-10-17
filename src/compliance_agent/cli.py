from __future__ import annotations

import argparses
import unicodedata
from datetime import datetime
from pathlib import Path
from textwrap import shorten

from colorama import Fore, Style, init as colorama_init

from compliance_agent import __version__
from compliance_agent.config import (
    configured_output_root,
    default_api_key_env,
    default_base_url,
    default_model,
    load_environment,
)
from compliance_agent.evaluation import evaluate_dataset
from compliance_agent.exporters import export_document
from compliance_agent.llm import LLMClient, LLMRequestError, LLMResponseError, LLMSettings
from compliance_agent.pipeline import run_pipeline, validation_summary_lines
from compliance_agent.validation import validate_export_pair


def main() -> None:
    colorama_init(autoreset=True)
    load_environment()
    _print_banner()

    parser = argparse.ArgumentParser(
        description="Extract structured security controls from policy documents.",
        epilog="Example:\n  python -m compliance_agent extract --input policy.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    extract_parser = subparsers.add_parser(
        "extract", help="Extract requirements from a policy or standard file."
    )
    extract_parser.add_argument(
        "--input", dest="input_path", help="Path to a .txt, .pdf, .docx, or .doc file."
    )
    extract_parser.add_argument(
        "--output-dir", dest="output_dir", help="Directory for generated JSON and YAML files."
    )
    extract_parser.add_argument(
        "--model", default=default_model(), help="OpenAI or compatible model name."
    )
    extract_parser.add_argument(
        "--base-url",
        default=default_base_url(),
        help="OpenAI-compatible base URL for local runtimes such as Ollama.",
    )
    extract_parser.add_argument(
        "--api-key-env",
        default=default_api_key_env(),
        help="Environment variable holding the API key.",
    )

    eval_parser = subparsers.add_parser(
        "evaluate", help="Evaluate the full pipeline against a reviewed dataset."
    )
    eval_parser.add_argument("--dataset", required=True, help="Path to the dataset JSON file.")
    eval_parser.add_argument("--mode", choices=["full", "baseline"], default="full")
    eval_parser.add_argument("--model", default=default_model())
    eval_parser.add_argument("--base-url", default=default_base_url())
    eval_parser.add_argument("--api-key-env", default=default_api_key_env())

    args = parser.parse_args()
    command = args.command or "extract"

    try:
        if command == "evaluate":
            settings = LLMSettings(
                model=args.model, base_url=args.base_url, api_key_env=args.api_key_env
            )
            client = LLMClient(settings)
            metrics = evaluate_dataset(Path(args.dataset), client, mode=args.mode)

            _print_header("Evaluation Summary")
            _print_kv("Mode", args.mode)
            _print_kv("Model", settings.model)
            _print_metric("Extraction precision", metrics.extraction_precision)
            _print_metric("Extraction recall", metrics.extraction_recall)
            _print_metric("Mapping precision", metrics.mapping_precision)
            _print_metric("Mapping recall", metrics.mapping_recall)
            _print_metric("Schema validity rate", metrics.schema_validity_rate)
            _print_metric("Output consistency rate", metrics.output_consistency_rate)
            _print_metric("Hallucination rate", metrics.hallucination_rate)
            return

        input_path = (
            Path(args.input_path)
            if args.input_path
            else Path(input("Enter the policy file path: ").strip())
        )
        output_dir = (
            Path(args.output_dir) if args.output_dir else _default_output_dir(input_path)
        )

        settings = LLMSettings(
            model=args.model, base_url=args.base_url, api_key_env=args.api_key_env
        )
        client = LLMClient(settings)

        _print_progress(1, 3, "Reading and analyzing document")
        document = run_pipeline(input_path, client)

        _print_progress(2, 3, "Writing JSON and YAML outputs")
        json_path, yaml_path = export_document(document, output_dir)
        export_report = validate_export_pair(json_path, yaml_path)

        _print_progress(3, 3, "Rendering summary")
        _print_header("Run Complete")
        _print_kv("Input", str(input_path))
        _print_kv("Mode", "hosted LLM")
        _print_kv("Model", settings.model)
        _print_kv("JSON", str(json_path))
        _print_kv("YAML", str(yaml_path))

        for line in validation_summary_lines(document):
            _print_status_line(line)

        _print_run_snapshot(document, export_report)
        _print_requirements_table(document.requirements)

        for issue in export_report.issues:
            _print_issue(issue.severity.upper(), issue.code, issue.message)

        if not export_report.issues:
            print(f"{Fore.GREEN}Export consistency: OK{Style.RESET_ALL}")

    except (LLMRequestError, LLMResponseError, ValueError, RuntimeError) as exc:
        print(f"{Fore.RED}Agent run failed: {Style.RESET_ALL}{exc}")
        raise SystemExit(1) from exc


def _default_output_dir(input_path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_root = configured_output_root() or (
        Path.home() / "Documents" / "ComplianceAgentOutputs"
    )
    return output_root / f"{input_path.stem}-{timestamp}"


def _print_banner() -> None:
    print(f"{Fore.CYAN}▶ Compliance Agent v{__version__}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Structured policy extraction and control mapping{Style.RESET_ALL}")
    print()


def _print_progress(step: int, total: int, label: str) -> None:
    print(f"{Fore.BLUE}• [{step}/{total}] {label}{Style.RESET_ALL}")


def _print_header(title: str) -> None:
    line = "=" * max(len(title) + 6, 28)
    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}≡ {title} ≡{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")


def _print_kv(label: str, value: str) -> None:
    print(f"{Style.BRIGHT}{label:<13}{Style.RESET_ALL} {value}")


def _print_metric(label: str, value: float) -> None:
    color = Fore.GREEN if value >= 0.9 else Fore.YELLOW if value >= 0.75 else Fore.RED
    icon = "✅" if value >= 0.9 else "⚠" if value >= 0.75 else "❌"
    print(f"{icon} {label:<26} {color}{value:.3f}{Style.RESET_ALL}")


def _print_status_line(line: str) -> None:
    if line.startswith("Validation status:"):
        ok = "PASS" in line
        color = Fore.GREEN if ok else Fore.RED
        print(f"{color}{line}{Style.RESET_ALL}")
        return
    if line.startswith("Requirements extracted:"):
        print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
        return
    if line.startswith("No validation issues detected."):
        print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
        return
    print(line)


def _print_run_snapshot(document, export_report) -> None:
    requirements = document.requirements
    mappings = _count_mappings(requirements)
    review_flags = _count_review_flags(requirements)
    issue_count = len(export_report.issues)
    status_text = "PASS" if not issue_count else "CHECK"
    status_icon = "✅" if not issue_count else "⚠"
    export_icon = "✅" if not issue_count else "⚠"

    rows = [
        f"{status_icon} Validation {status_text}",
        f"🧩 Mappings {mappings}",
        f"📝 Review flags {review_flags}",
        f"📄 Requirements {len(requirements)}",
        f"{export_icon} Export {'OK' if not issue_count else 'issues found'}",
    ]
    width = max(_display_width(row) for row in rows) + 4
    border = "┌" + "─" * width + "┐"

    print()
    print(f"{Fore.CYAN}{border}{Style.RESET_ALL}")
    title = " Run Snapshot "
    title_line = title.center(width, " ")
    print(
        f"{Fore.CYAN}│{Style.RESET_ALL}{Style.BRIGHT}{title_line}{Style.RESET_ALL}"
        f"{Fore.CYAN}│{Style.RESET_ALL}"
    )
    print(f"{Fore.CYAN}├" + "─" * width + f"┤{Style.RESET_ALL}")
    for row in rows:
        print(
            f"{Fore.CYAN}│{Style.RESET_ALL} {_pad_display(row, width - 2)} {Fore.CYAN}│{Style.RESET_ALL}"
        )
    print(f"{Fore.CYAN}└" + "─" * width + f"┘{Style.RESET_ALL}")


def _print_issue(severity: str, code: str, message: str) -> None:
    color = (
        Fore.RED
        if severity == "ERROR"
        else Fore.YELLOW
        if severity == "WARNING"
        else Fore.CYAN
    )
    print(f"{color}- {severity} {code}: {message}{Style.RESET_ALL}")


def _print_requirements_table(requirements) -> None:
    if not requirements:
        print(f"{Fore.YELLOW}⚠ No requirements extracted.{Style.RESET_ALL}")
        return

    print()
    _print_header("Requirements")

    columns = [
        ("ID", 10),
        ("Priority", 9),
        ("Conf", 7),
        ("Maps", 6),
        ("Review", 9),
        ("Status", 13),
        ("Domain", 20),
        ("Summary", 46),
    ]
    widths = [width for _, width in columns]

    print(_box_top(widths))
    print(_box_row([name for name, _ in columns], widths, header=True))
    print(_box_separator(widths))

    for requirement in requirements:
        summary = shorten(
            requirement.normalized_statement or requirement.title,
            width=46,
            placeholder="...",
        )
        color = _confidence_color(
            requirement.confidence,
            requirement.ambiguity_flags,
            requirement.needs_human_review,
        )
        review_flag = "YES" if requirement.needs_human_review else "NO"
        status_text, status_icon = _requirement_status(
            requirement.confidence,
            requirement.ambiguity_flags,
            requirement.needs_human_review,
        )
        cells = [
            f"{requirement.requirement_id}",
            f"{requirement.priority}",
            f"{requirement.confidence:.3f}",
            f"{len(requirement.mappings)}",
            review_flag,
            f"{status_icon} {status_text}",
            shorten(requirement.security_domain, width=20, placeholder="..."),
            summary,
        ]
        print(_box_row(cells, widths, color=color))

    print(_box_bottom(widths))


def _confidence_color(
    confidence: float, ambiguity_flags: list[str], needs_review: bool
) -> str:
    if needs_review or ambiguity_flags or confidence < 0.75:
        return Fore.YELLOW if confidence > 0.5 else Fore.RED
    if confidence >= 0.9:
        return Fore.GREEN
    return Fore.CYAN


def _requirement_status(
    confidence: float, ambiguity_flags: list[str], needs_review: bool
) -> tuple[str, str]:
    if needs_review or ambiguity_flags or confidence < 0.75:
        return ("Review", "⚠")
    if confidence >= 0.9:
        return ("Strong", "✅")
    return ("Moderate", "ℹ")


def _count_mappings(requirements) -> int:
    return sum(len(requirement.mappings) for requirement in requirements)


def _count_review_flags(requirements) -> int:
    return sum(
        1
        for requirement in requirements
        if requirement.needs_human_review or requirement.ambiguity_flags
    )


def _display_width(text: str) -> int:
    """Return how many terminal columns the text occupies (emoji count as 2)."""
    width = 0
    for char in text:
        if unicodedata.combining(char) or char in "\u200d\ufe0f":
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def _pad_display(text: str, width: int) -> str:
    return text + " " * max(width - _display_width(text), 0)


def _box_top(widths: list[int]) -> str:
    return "┌" + "┬".join("─" * (width + 2) for width in widths) + "┐"


def _box_separator(widths: list[int]) -> str:
    return "├" + "┼".join("─" * (width + 2) for width in widths) + "┤"


def _box_bottom(widths: list[int]) -> str:
    return "└" + "┴".join("─" * (width + 2) for width in widths) + "┘"


def _box_row(
    values: list[str], widths: list[int], header: bool = False, color: str = ""
) -> str:
    padded = []
    for value, width in zip(values, widths):
        if header:
            padded.append(f" {Style.BRIGHT}{_pad_display(value, width)}{Style.RESET_ALL} ")
        else:
            padded.append(f" {color}{_pad_display(value, width)}{Style.RESET_ALL} ")
    return "│" + "│".join(padded) + "│"


if __name__ == "__main__":
    main()
