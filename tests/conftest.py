from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def sample_policy(tmp_path: Path) -> Path:
    file_path = tmp_path / "policy.txt"
    file_path.write_text(
        "Only authorized administrators may access management interfaces.\n"
        "Employees must not access the production database directly from external networks.\n"
        "Sensitive systems should be adequately protected.\n",
        encoding="utf-8",
    )
    return file_path
