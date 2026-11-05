# Compliance Intelligence Platform

Compliance Intelligence Platform is a Python-based compliance and security policy analysis platform that ingests policy content, extracts requirement statements, maps them to known framework controls, detects contradictions, scores risk posture, and presents the results through a Streamlit dashboard and CLI workflow.

It is built for security, governance, and audit teams that need to turn policy language into structured, reviewable, and comparable compliance evidence.

## Why this project exists

Security policies are usually written for human review, not for automation. That creates several issues:

1. Requirements are described inconsistently across documents
2. Policy text is hard to compare against established frameworks
3. Missing or conflicting controls are not obvious until manual review
4. Leadership teams need faster visibility into risk posture and coverage gaps

This project solves that by creating a repeatable compliance intelligence workflow that takes policy documents and turns them into structured evidence and actionable reports.

## Core platform capabilities

The platform now includes the following layers:

- Multi-document policy repository ingestion
- Framework coverage matrix mapping
- Conflict detection across extracted policy statements
- Human review workflow with approval-state tracking
- Report bundle generation for CSV, Excel, and PDF outputs
- Executive risk scoring and posture evaluation
- Streamlit dashboard for policy analysis and reporting
- CLI execution for local policy extraction and validation

## Problem domain

The platform supports policy, standard, and control text from files such as:

- `.txt`
- `.pdf`
- `.docx`
- `.doc` on Windows when Word integration is available

It works best with documents that describe obligations, restrictions, security requirements, access constraints, logging rules, incident handling requirements, and other governance-based controls.

## How it works

The workflow is designed as a compliance intelligence pipeline:

1. Load one or more policy files or a policy directory.
2. Extract natural-language requirements from the source content.
3. Normalize each requirement into a standard schema.
4. Map requirements to known control frameworks when a valid match exists.
5. Validate data quality, conflicts, coverage gaps, and review requirements.
6. Score the result against a built-in risk model.
7. Save structured outputs to JSON and YAML.
8. Generate summary, coverage, and review reports.
9. Display the results through the dashboard or the CLI.

## Product features

### 1. Multi-document repository ingestion

The repository ingestion layer can ingest a folder of policy documents and normalize them into a common compliance structure. This makes the platform useful for evaluating multiple files at once instead of only a single document.

### 2. Control coverage matrix by framework

The coverage engine builds a control-by-framework matrix showing which controls are present, which are missing, and what coverage rate is achieved by the analyzed policy set.

### 3. Conflict detection

The tool can detect contradictory or overlapping protections within the same domain. This helps security teams identify places where the policy language may be internally inconsistent.

### 4. Human review workflow

Requirements that are ambiguous, weakly supported, or potentially risky are automatically queued for human review. This review layer supports a simple approval-state model so analysts can track what still needs attention.

### 5. Reporting exports

The reporting layer creates export bundles including:

- CSV summary export
- Excel workbook with summary and framework coverage data
- PDF summary report

### 6. Risk scoring engine

A scoring engine evaluates rule coverage, clarity, priority, and evidence quality to calculate an overall risk score and risk classification. This enables more executive-friendly risk reporting than a raw requirement list alone.

### 7. Dashboard and UI

The project includes a Streamlit dashboard that provides a practical interface for:

- Selecting a policy folder or file path
- Running the compliance analysis
- Viewing the requirements table
- Seeing the risk score and risk level
- Checking output paths for generated JSON and YAML files
- Reviewing coverage, conflicts, review queue, and reports tabs

## Project structure

```text
Personal Project/
    app.py
    .env.example
    datasets/
    src/
        compliance_agent/
    tests/
    pyproject.toml
    requirements.txt
    README.md
    .env
```

Key modules:

- `app.py`: Streamlit dashboard entry point
- `src/compliance_agent/cli.py`: terminal CLI for command-line workflow
- `src/compliance_agent/config.py`: environment and output configuration
- `src/compliance_agent/llm.py`: OpenAI-compatible LLM client and error handling
- `src/compliance_agent/pipeline.py`: orchestration for extraction, validation, and correction
- `src/compliance_agent/models.py`: canonical requirement and document schema
- `src/compliance_agent/engine.py`: scoring and risk logic
- `src/compliance_agent/repository.py`: multi-document repository ingestion
- `src/compliance_agent/coverage.py`: coverage matrix generation
- `src/compliance_agent/conflicts.py`: conflict detection
- `src/compliance_agent/review.py`: human review queue and status tracking
- `src/compliance_agent/reporting.py`: CSV, Excel, and PDF report generation
- `src/compliance_agent/exporters.py`: JSON and YAML export writing
- `src/compliance_agent/validation.py`: validation logic and consistency checks

## Prerequisites

The project is designed for Python 3.11 or later. Python 3.13 is also supported.

Before running the project, make sure:

- Python is installed and available on PATH
- Git is installed
- A virtual environment is created for the project
- Your `.env` file contains the required model credentials

## Setup

### 1. Clone the repository

```powershell
git clone <your-repo-url>
cd "Personal Project"
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the environment

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a local `.env` file from the example:

```powershell
Copy-Item .env.example .env
```

Example settings:

```env
OPENAI_API_KEY=your-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=
COMPLIANCE_AGENT_OUTPUT_DIR=C:\Users\your-user\Documents\ComplianceAgentOutputs
COMPLIANCE_AGENT_API_KEY_ENV=OPENAI_API_KEY
```

## How to run the application

### Run the Streamlit dashboard

From the project root:

```powershell
python -m streamlit run app.py --server.headless true --server.port 8001
```

Then open the local URL shown in the terminal, typically:

```text
http://localhost:8001
```

The dashboard includes:

- A sidebar input for the security controls directory path
- Automatic file resolution from the selected directory
- The extracted requirement table
- Risk score and risk level cards
- Validation and output path display
- Coverage, conflicts, review queue, and reports tabs

### Run the CLI workflow

From the project root:

```powershell
python -m compliance_agent extract --input .\datasets\evaluation\policies\access_control.txt
```

If no file path is provided, the CLI can prompt for one interactively.

### Run the tests

```powershell
python -m pytest
```

## Supported output artifacts

Each run generates structured outputs in a timestamped folder under the configured output directory. Default output root is:

```text
%USERPROFILE%\Documents\ComplianceAgentOutputs
```

Generated artifacts include:

- JSON validation output
- YAML export output
- CSV summary report
- Excel workbook with summary and coverage data
- PDF summary report

## Validation and review behavior

The validation layer enforces consistency and safety before exporting data. It checks for:

- Missing required fields
- Duplicate requirements
- Unsupported mappings
- Weak evidence or ambiguous wording
- Conflicting statements in the same domain
- Incomplete or risky requirement logic

Ambiguous or weaker outputs are flagged for human review rather than silently accepted.

## Security notes

- Input files are treated as untrusted content.
- Raw LLM output is normalized and validated before export.
- Sensitive policy files should remain local unless there is an approved secure transfer path.
- Do not commit `.env` files or hardcode API keys in code or documentation.

## Current state

This project is now a full compliance intelligence platform rather than a single-purpose extraction script. It combines policy analysis, scoring, validation, reporting, and a dashboard in a single local workflow suitable for demo, internal review, and further extension into enterprise governance tooling.
