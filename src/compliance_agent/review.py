from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from compliance_agent.models import SecurityRequirement


@dataclass(slots=True)
class ReviewItem:
    requirement_id: str
    document: str
    status: str = "pending"
    reviewer: str | None = None
    notes: str = ""
    reviewed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def create_review_queue(requirements: list[SecurityRequirement]) -> list[ReviewItem]:
    items: list[ReviewItem] = []
    for requirement in requirements:
        if requirement.needs_human_review or requirement.ambiguity_flags:
            items.append(
                ReviewItem(
                    requirement_id=requirement.requirement_id,
                    document="source-document",
                    status="pending",
                    reviewer=None,
                    notes="; ".join(requirement.ambiguity_flags)
                    if requirement.ambiguity_flags
                    else "",
                )
            )
    return items


def update_review_status(
    item: ReviewItem,
    status: str,
    reviewer: str | None = None,
    notes: str | None = None,
) -> ReviewItem:
    item.status = status
    item.reviewer = reviewer
    item.notes = notes or item.notes
    item.reviewed_at = datetime.now(timezone.utc).isoformat()
    return item
