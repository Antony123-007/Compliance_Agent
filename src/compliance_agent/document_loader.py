from __future__ import annotations

from pathlib import Path

from docx import Document
from pypdf import PdfReader


def load_text(path: Path) -> str:
    suffix = path.suffix.lower()

    if suffix == ".txt":
        return path.read_text(encoding="utf-8")

    if suffix == ".pdf":
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    if suffix == ".docx":
        document = Document(str(path))
        return "\n".join(paragraph.text for paragraph in document.paragraphs)

    if suffix == ".doc":
        return _load_legacy_word(path)

    raise ValueError(
        f"Unsupported file type: {suffix}. Supported types are .txt, .pdf, .docx, and .doc"
    )


def _load_legacy_word(path: Path) -> str:
    try:
        import win32com.client  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ValueError(
            "Legacy .doc support requires pywin32 and Microsoft Word on Windows. "
            "Convert the file to .docx or install the dependency."
        ) from exc

    word = win32com.client.Dispatch("Word.Application")
    word.Visible = False
    document = None
    temp_path = path.with_suffix(".txt")

    try:
        document = word.Documents.Open(str(path.resolve()))
        document.SaveAs(str(temp_path.resolve()), FileFormat=2)
        return temp_path.read_text(encoding="utf-8", errors="ignore")
    finally:
        if document is not None:
            document.Close(False)
        word.Quit()
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
