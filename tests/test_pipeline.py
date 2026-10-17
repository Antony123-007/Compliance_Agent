from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from compliance_agent.pipeline import run_pipeline


class FakeClient:
    def __init__(self) -> None:
        self.settings = SimpleNamespace(provider_name="test", model="fake-model")

    def extract(self, source_name: str, text: str) -> dict:
        return {
            "requirements": [
                {
                    "requirement_id": "TEMP-1",
                    "title": "Restrict admin access",
                    "source_text": "Only authorized administrators may access management interfaces.",
                    "normalized_statement": "Restrict management interface access to authorized administrators only.",
                    "intent": "Reduce unauthorized privileged access.",
                    "security_domain": "Access Control",
                    "subject": "authorized administrators",
                    "action": "access",
                    "resource": "management interfaces",
                    "conditions": ["authorized administrators only"],
                    "exceptions": [],
                    "priority": "high",
                    "confidence": 0.92,
                    "ambiguity_flags": [],
                    "needs_human_review": False,
                    "evidence": ["Explicitly restricts access to management interfaces."],
                    "mappings": [
                        {
                            "framework": "NIST CSF 2.0",
                            "version": "2.0",
                            "control_id": "PR.AA-05",
                            "control_title": "Access permissions are limited",
                            "relation": "exact",
                            "rationale": "Administrative access restriction is explicit.",
                        }
                    ],
                    "rejected_mappings": [],
                },
                {
                    "requirement_id": "TEMP-2",
                    "title": "Block direct external DB access",
                    "source_text": "Employees must not access the production database directly from external networks.",
                    "normalized_statement": "Prevent employees from accessing the production database directly from external networks.",
                    "intent": "Prevent unsafe external access to production data stores.",
                    "security_domain": "Network Security",
                    "subject": "employees",
                    "action": "must not access",
                    "resource": "production database",
                    "conditions": ["from external networks"],
                    "exceptions": [],
                    "priority": "high",
                    "confidence": 0.9,
                    "ambiguity_flags": [],
                    "needs_human_review": False,
                    "evidence": ["Direct external database access is prohibited."],
                    "mappings": [
                        {
                            "framework": "CIS Controls",
                            "version": "8.1",
                            "control_id": "CIS 12",
                            "control_title": "Network Infrastructure Management",
                            "relation": "partial",
                            "rationale": "The requirement constrains network-based access paths.",
                        }
                    ],
                    "rejected_mappings": [],
                },
                {
                    "requirement_id": "TEMP-3",
                    "title": "Protect sensitive systems",
                    "source_text": "Sensitive systems should be adequately protected.",
                    "normalized_statement": "Protect sensitive systems with appropriate safeguards.",
                    "intent": "Protect important systems.",
                    "security_domain": "System Security",
                    "subject": None,
                    "action": "protect",
                    "resource": "sensitive systems",
                    "conditions": [],
                    "exceptions": [],
                    "priority": "medium",
                    "confidence": 0.55,
                    "ambiguity_flags": [],
                    "needs_human_review": False,
                    "evidence": ["The sentence requests protection but does not define controls."],
                    "mappings": [
                        {
                            "framework": "Unknown Framework",
                            "version": "1.0",
                            "control_id": "UF-1",
                            "control_title": "Unsupported",
                            "relation": "related",
                            "rationale": "Invalid test mapping.",
                        }
                    ],
                    "rejected_mappings": [],
                },
                {
                    "requirement_id": "TEMP-4",
                    "title": "Permit external database access",
                    "source_text": "Employees may access the production database from external networks when approved.",
                    "normalized_statement": "Employees may access the production database from external networks when approved.",
                    "intent": "Allow approved remote access.",
                    "security_domain": "Network Security",
                    "subject": "employees",
                    "action": "may access",
                    "resource": "production database",
                    "conditions": ["from external networks", "when approved"],
                    "exceptions": [],
                    "priority": "medium",
                    "confidence": 0.64,
                    "ambiguity_flags": [],
                    "needs_human_review": False,
                    "evidence": ["Conditional allowance for external access."],
                    "mappings": [],
                    "rejected_mappings": [],
                },
            ]
        }

    def correct(self, validation_errors: list[str], raw_response: str) -> dict:
        raise AssertionError("Correction should not be called in this test")


def test_pipeline_extracts_and_flags_review(sample_policy: Path) -> None:
    document = run_pipeline(sample_policy, FakeClient())

    assert len(document.requirements) == 4
    assert document.requirements[0].requirement_id == "REQ-0001"
    assert document.requirements[2].needs_human_review is True
    assert document.requirements[2].rejected_mappings[0].control_id == "UF-1"
    assert any(issue.code == "unsupported_mapping" for issue in document.validation_report.issues)
    assert any(issue.code == "conflicting_requirement" for issue in document.validation_report.issues)
