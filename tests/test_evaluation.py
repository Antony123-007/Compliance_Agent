from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from compliance_agent.evaluation import evaluate_dataset


class FakeEvalClient:
    def __init__(self) -> None:
        self.settings = SimpleNamespace(provider_name="test", model="fake model")

    def extract(self, source_name: str, text: str) -> dict:
        if source_name == "conflict_policy.txt":
            return {
                "requirements": [
                    {
                        "requirement_id": "TEMP-1",
                        "title": "Allow approved remote finance access",
                        "source_text": "Remote employees may access the finance portal from external networks when approved.",
                        "normalized_statement": "Remote employees may access the finance portal from external networks when approved.",
                        "intent": "Permit approved remote access to the finance portal.",
                        "security_domain": "Access Control",
                        "subject": "remote employees",
                        "action": "may access",
                        "resource": "finance portal",
                        "conditions": ["from external networks", "when approved"],
                        "exceptions": [],
                        "priority": "medium",
                        "confidence": 0.88,
                        "ambiguity_flags": [],
                        "needs_human_review": False,
                        "evidence": ["Conditional remote access is allowed."],
                        "mappings": [
                            {
                                "framework": "NIST CSF 2.0",
                                "version": "2.0",
                                "control_id": "PR.AA-03",
                                "control_title": "Access to assets is managed",
                                "relation": "partial",
                                "rationale": "Approved remote access management.",
                            },
                            {
                                "framework": "CIS Controls",
                                "version": "8.1",
                                "control_id": "CIS 6",
                                "control_title": "Access Control Management",
                                "relation": "partial",
                                "rationale": "Access rights are controlled.",
                            },
                        ],
                        "rejected_mappings": [],
                    },
                    {
                        "requirement_id": "TEMP-2",
                        "title": "Deny remote finance access",
                        "source_text": "Remote employees must not access the finance portal from external networks.",
                        "normalized_statement": "Remote employees must not access the finance portal from external networks.",
                        "intent": "Prohibit remote external access to the finance portal.",
                        "security_domain": "Access Control",
                        "subject": "remote employees",
                        "action": "must not access",
                        "resource": "finance portal",
                        "conditions": ["from external networks"],
                        "exceptions": [],
                        "priority": "high",
                        "confidence": 0.91,
                        "ambiguity_flags": [],
                        "needs_human_review": False,
                        "evidence": ["External remote access is prohibited."],
                        "mappings": [
                            {
                                "framework": "NIST CSF 2.0",
                                "version": "2.0",
                                "control_id": "PR.AA-05",
                                "control_title": "Access permissions are limited",
                                "relation": "exact",
                                "rationale": "Access is explicitly restricted.",
                            },
                            {
                                "framework": "CIS Controls",
                                "version": "8.1",
                                "control_id": "CIS 12",
                                "control_title": "Network Infrastructure Management",
                                "relation": "partial",
                                "rationale": "External network access is constrained.",
                            },
                        ],
                        "rejected_mappings": [],
                    },
                ]
            }

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
                    "evidence": ["Explicit restriction."],
                    "mappings": [
                        {
                            "framework": "NIST CSF 2.0",
                            "version": "2.0",
                            "control_id": "PR.AA-05",
                            "control_title": "Access permissions are limited",
                            "relation": "exact",
                            "rationale": "Match",
                        },
                        {
                            "framework": "CIS Controls",
                            "version": "8.1",
                            "control_id": "CIS 6",
                            "control_title": "Access Control Management",
                            "relation": "partial",
                            "rationale": "Match",
                        },
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
                    "evidence": ["Explicit prohibition."],
                    "mappings": [
                        {
                            "framework": "CIS Controls",
                            "version": "8.1",
                            "control_id": "CIS 12",
                            "control_title": "Network Infrastructure Management",
                            "relation": "partial",
                            "rationale": "Match",
                        },
                        {
                            "framework": "NIST CSF 2.0",
                            "version": "2.0",
                            "control_id": "PR.AA-05",
                            "control_title": "Access permissions are limited",
                            "relation": "related",
                            "rationale": "Match",
                        },
                    ],
                    "rejected_mappings": [],
                },
            ]
        }

    def baseline_extract(self, source_name: str, text: str) -> dict:
        return self.extract(source_name, text)

    def correct(self, validation_errors: list[str], raw_response: str) -> dict:
        raise AssertionError("Correction should not be called in this test")


def test_evaluation_metrics_are_computed() -> None:
    dataset = Path("datasets/evaluation/cases.json")
    metrics = evaluate_dataset(dataset, FakeEvalClient(), mode="full")

    assert metrics.extraction_precision == 1.0
    assert metrics.extraction_recall == 1.0
    assert metrics.mapping_precision == 1.0
    assert metrics.mapping_recall == 1.0
    assert metrics.schema_validity_rate == 1.0
    assert metrics.output_consistency_rate == 1.0
    assert metrics.hallucination_rate == 0.0
    assert metrics.human_review_rate > 0.0
    assert metrics.conflict_detection_recall == 1.0
