from __future__ import annotations

import re
from collections import defaultdict

from compliance_agent.models import ControlMapping, FrameworkControl, SecurityRequirement

FRAMEWORK_CATALOG: list[FrameworkControl] = [
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.AA-01",
        title="Identities and credentials are managed",
        summary="Manage user and service identities with approved authorization practices.",
        tags=["identity", "access", "account", "credential", "administrator", "authorized"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.AA-05",
        title="Access permissions are limited",
        summary="Restrict access to systems and data based on business need.",
        tags=["least privilege", "restrict", "access", "permission", "approved users"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.DS-01",
        title="Data at rest is protected",
        summary="Protect stored data through technical safeguards.",
        tags=["data", "database", "storage", "encryption", "sensitive"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.PS-01",
        title="Configuration baselines are managed",
        summary="Maintain secure configurations for platforms and services.",
        tags=["configuration", "hardening", "baseline", "system", "service"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="DE.CM-01",
        title="Networks and environments are monitored",
        summary="Monitor networks and execution environments for security events.",
        tags=["monitoring", "network", "logging", "detection", "event"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.IR-01",
        title="Recovery and response plans are exercised",
        summary="Prepare and maintain response and recovery practices.",
        tags=["incident", "response", "recovery", "plan", "exercise"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="GV.PO-01",
        title="Policy for cybersecurity risk management is established",
        summary="Establish and communicate cybersecurity policy expectations.",
        tags=["policy", "governance", "standard", "procedure", "requirement"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.AA-03",
        title="Access to assets is managed",
        summary="Manage physical and logical access to assets and associated facilities.",
        tags=["access", "asset", "remote", "facility", "logical access"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="PR.PS-04",
        title="Software and hardware are maintained securely",
        summary="Maintain platforms and services with secure lifecycle and timely patching.",
        tags=["patch", "update", "maintenance", "software", "firmware"],
    ),
    FrameworkControl(
        framework="NIST CSF 2.0",
        version="2.0",
        control_id="RC.RP-01",
        title="Recovery processes are executed and maintained",
        summary="Execute and maintain backup and recovery procedures.",
        tags=["backup", "restore", "recovery", "business continuity", "resilience"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 5",
        title="Account Management",
        summary="Use processes to manage the lifecycle of user and system accounts.",
        tags=["account", "user", "administrator", "credential", "authorized"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 6",
        title="Access Control Management",
        summary="Establish and maintain access rights for assets and data.",
        tags=["access", "permission", "authorized", "least privilege", "approved users"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 12",
        title="Network Infrastructure Management",
        summary="Manage and protect network devices and services.",
        tags=["network", "firewall", "port", "service", "segmentation", "external"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 13",
        title="Network Monitoring and Defense",
        summary="Monitor and defend network traffic and network-based threats.",
        tags=["network", "monitoring", "traffic", "detection", "logging"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 3",
        title="Data Protection",
        summary="Protect data throughout its lifecycle.",
        tags=["data", "database", "sensitive", "encryption", "storage"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 17",
        title="Incident Response Management",
        summary="Develop and exercise incident response capabilities.",
        tags=["incident", "response", "recovery", "plan", "communication"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 4",
        title="Secure Configuration of Enterprise Assets and Software",
        summary="Establish and maintain secure configuration standards.",
        tags=["configuration", "baseline", "hardening", "secure configuration", "standard"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 7",
        title="Continuous Vulnerability Management",
        summary="Assess and remediate vulnerabilities including missing patches.",
        tags=["vulnerability", "patch", "update", "remediation", "fix"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 11",
        title="Data Recovery",
        summary="Establish and test recovery processes for backed up data.",
        tags=["backup", "recovery", "restore", "data recovery", "restore test"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 14",
        title="Security Awareness and Skills Training",
        summary="Train workforce members on security responsibilities and risks.",
        tags=["training", "awareness", "phishing", "employee", "education"],
    ),
    FrameworkControl(
        framework="CIS Controls",
        version="8.1",
        control_id="CIS 15",
        title="Service Provider Management",
        summary="Manage the security responsibilities of external service providers.",
        tags=["vendor", "third party", "service provider", "supplier", "external access"],
    ),
]


def catalog_by_key() -> dict[tuple[str, str], FrameworkControl]:
    return {(control.framework, control.control_id): control for control in FRAMEWORK_CATALOG}


def catalog_summary() -> list[dict[str, str]]:
    return [
        {
            "framework": control.framework,
            "version": control.version,
            "control_id": control.control_id,
            "title": control.title,
            "summary": control.summary,
        }
        for control in FRAMEWORK_CATALOG
    ]


def _tokenize(value: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) > 2}


def suggest_mappings(requirement: SecurityRequirement, limit: int = 3) -> list[ControlMapping]:
    search_text = " ".join(
        [
            requirement.title,
            requirement.normalized_statement,
            requirement.intent,
            requirement.security_domain,
            requirement.subject or "",
            requirement.action,
            requirement.resource or "",
            " ".join(requirement.conditions),
        ]
    )
    tokens = _tokenize(search_text)

    scored: dict[int, list[FrameworkControl]] = defaultdict(list)
    for control in FRAMEWORK_CATALOG:
        score = len(
            tokens.intersection(
                _tokenize(" ".join(control.tags + [control.title, control.summary]))
            )
        )
        if score >= 2:
            scored[score].append(control)

    mappings: list[ControlMapping] = []
    for score in sorted(scored.keys(), reverse=True):
        for control in scored[score]:
            relation = "exact" if score > 5 else "partial" if score >= 3 else "related"
            mappings.append(
                ControlMapping(
                    framework=control.framework,
                    version=control.version,
                    control_id=control.control_id,
                    control_title=control.title,
                    relation=relation,
                    rationale=f"Keyword overlap score {score} based on local framework catalog.",
                )
            )
            if len(mappings) >= limit:
                return mappings

    return mappings
