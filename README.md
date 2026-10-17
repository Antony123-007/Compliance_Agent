# Compliance Agent

Compliance Agent is a local Python command-line tool that reads security policy documents, extracts structured security requirements, normalizes them into a consistent schema, maps them to a curated control catalog, validates the results, and exports the final output as JSON and YAML.

It is designed for teams that want to turn long policy text into machine-readable compliance data without losing traceability, reviewability, or human oversight.

## What this project solves

Security and compliance documents are usually written for people, not software. That creates three common problems:

1. The same rule is described in many different ways.
2. Requirements are hard to compare across documents and frameworks.
3. Manual review is slow, inconsistent, and easy to drift over time.

This agent addresses that by converting policy text into a repeatable structured workflow. It extracts individual requirements, captures confidence and traceability, maps requirements to known controls, flags ambiguity for human review, and writes validated output files that can be reused downstream.

## LLM agent overview

This project includes an LLM-powered compliance agent that acts as an intelligent extraction and interpretation layer for security policy documents. The agent is not just a generic chatbot; it is built to read real policy content and convert it into a structured compliance model that can be validated, reviewed, and reused in downstream systems.

In practical terms, the agent takes a policy document or security standard as input, analyzes the text for obligations, restrictions, and control requirements, and produces normalized security requirements that can be mapped to known frameworks and exported to machine-readable formats.

The agent is designed to be careful and controlled. Instead of blindly inventing information, it:

- reads the source document and identifies explicit obligations and constraints
- extracts relevant compliance requirements in a consistent schema
- assigns confidence levels to the extracted output
- identifies ambiguous or weakly supported requirements for human review
- maps the extracted requirement to relevant framework controls when a valid match exists
- validates the output before saving JSON and YAML exports

This makes it useful for security teams, compliance analysts, auditors, and engineering leaders who need a faster and more consistent way to convert policy language into structured evidence and control mappings.

## What the agent does

At a high level, the agent:

- reads a policy file from disk
- sends the document text to an OpenAI-compatible LLM
- asks the model to extract structured requirements
- normalizes the result into a canonical Pydantic schema
- maps each requirement to a supported security framework control when possible
- validates the output for missing fields, unsupported mappings, duplicates, ambiguity, and conflicts
- writes JSON and YAML exports to a timestamped output folder
- prints a readable terminal summary with status badges and a requirements table

## What kinds of input it accepts

The CLI currently supports these input formats:

- `.txt`
- `.pdf`
- `.docx`
- `.doc` on Windows when Microsoft Word and `pywin32` are available

The agent is built to accept policy language, standards text, control descriptions, and similar compliance content. It works best when the input contains explicit obligations, restrictions, thresholds, exceptions, or evidence requirements.

## What the output looks like

Each extraction run produces:

- a JSON file containing the validated structured document
- a YAML file with the same content for easier human review
- a terminal summary showing validation status, mapping counts, review flags, and export consistency
- a boxed requirements table with confidence, mapping counts, review status, security domain, and a short requirement summary

The output folder is timestamped so each run is preserved separately. By default it is written under your Documents folder, unless you override the root with `COMPLIANCE_AGENT_OUTPUT_DIR`.

## How the LLM pipeline works

The LLM side of the project is intentionally constrained.

The prompt asks the model to extract requirements into a structured schema rather than free-form prose. The code then validates and normalizes the response so the result is consistent and machine-friendly. If a requirement is ambiguous, incomplete, or risky, the pipeline flags it for human review instead of trying to invent missing detail.

The hosted model path uses these environment variables:

- `OPENAI_API_KEY` for authentication
- `OPENAI_MODEL` for the default model name
- `OPENAI_BASE_URL` for OpenAI-compatible local or hosted runtimes

The app loads `.env` automatically at startup. That keeps local secrets out of the command line and makes the CLI easier to run on a fresh machine.

## Project structure

```text
Personal_Project/
├── .env.example
├── datasets/
│   └── evaluation/
├── pyproject.toml
├── requirements.txt
├── src/
│   └── compliance_agent/
└── tests/
```

Key code areas:

- `src/compliance_agent/cli.py`: command-line entry point and terminal presentation
- `src/compliance_agent/config.py`: env loading and runtime defaults
- `src/compliance_agent/document_loader.py`: text, PDF, and Word document ingestion
- `src/compliance_agent/prompts.py`: prompt templates and extraction guidance
- `src/compliance_agent/llm.py`: OpenAI client wrapper and error translation
- `src/compliance_agent/models.py`: canonical Pydantic schema definitions
- `src/compliance_agent/frameworks.py`: curated control catalog and mapping support
- `src/compliance_agent/validation.py`: requirement and export validation rules
- `src/compliance_agent/exporters.py`: JSON and YAML output writing
- `src/compliance_agent/pipeline.py`: extraction, correction, and summary flow
- `src/compliance_agent/evaluation.py`: dataset-level metrics and baseline comparison

## Prerequisites

Install these before setting up the project:

1. Python 3.11 or later. Python 3.13 works well with the current setup.
2. Git.
3. Windows PowerShell or Command Prompt.

Check your Python installation with:

```powershell
python --version
```

## Step-by-step setup on a local machine

### 1. Clone the repository

```powershell
git clone <your-repo-url>
cd Personal_Project
```

### 2. Create a virtual environment

PowerShell:

```powershell
python -m venv .venv
```

Command Prompt:

```cmd
python -m venv .venv
```

### 3. Activate the virtual environment

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

If PowerShell blocks script execution, allow local scripts once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

The requirements file installs the project in editable mode and pulls the development dependencies from `pyproject.toml`.

### 5. Create your local `.env`

Copy the example file:

```powershell
Copy-Item .env.example .env
```

Then edit `.env` and add your real API key and any optional overrides.

### 6. Run a smoke test

Use the bundled sample policy file:

```powershell
python -m compliance_agent extract --input datasets\evaluation\policies\access_control.txt
```

### 7. Run the tests

```powershell
python -m pytest
```

## Configuration

The most important environment variables are:

- `OPENAI_API_KEY`: required for hosted LLM runs
- `OPENAI_MODEL`: default model name, such as `gpt-4.1-mini`
- `OPENAI_BASE_URL`: optional base URL for compatible providers or local runtimes
- `COMPLIANCE_AGENT_OUTPUT_DIR`: optional output root for generated files
- `COMPLIANCE_AGENT_API_KEY_ENV`: optional name of the environment variable that stores the API key

Example `.env`:

```env
OPENAI_API_KEY=your-real-openai-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=
COMPLIANCE_AGENT_OUTPUT_DIR=C:\Users\your-user\Documents\ComplianceAgentOutputs
COMPLIANCE_AGENT_API_KEY_ENV=OPENAI_API_KEY
```

## Command reference

### Extract requirements from a document

```powershell
python -m compliance_agent extract --input datasets\evaluation\policies\access_control.txt
```

If you omit `--input`, the CLI will prompt for a file path.

Common optional flags:

- `--output-dir` to choose a custom output folder
- `--model` to override the model name
- `--base-url` to use a compatible non-OpenAI endpoint
- `--api-key-env` to point at a different API key variable

### Evaluate the reviewed dataset

```powershell
python -m compliance_agent evaluate --dataset .\datasets\evaluation\cases.json --mode full
python -m compliance_agent evaluate --dataset .\datasets\evaluation\cases.json --mode baseline
```

The `full` mode uses the hosted pipeline. The `baseline` mode runs a lower-capability comparison path for evaluation.

## How the codebase is organized

The project is built as a small but complete compliance intelligence pipeline.

The document loader reads supported files and turns them into plain text. The prompt layer tells the model what to extract and how to structure it. The model wrapper handles API requests and turns provider errors into clearer messages. The pipeline assembles the extraction result, applies validation and correction when needed, and returns a canonical document object. The exporter then writes that object to JSON and YAML. The CLI is responsible for the human-facing terminal experience.

The schema includes fields for requirement IDs, titles, normalized statements, priority, security domain, confidence, mappings, evidence, traceability, and review status. That structure is what makes the output useful for downstream automation and human audit work.

## Validation and review behavior

The validation layer is intentionally conservative. It checks for things like:

- missing required fields
- duplicate requirements
- unsupported framework mappings
- traceability gaps
- prompt-like text embedded in source content
- ambiguous or underspecified requirements
- conflicting requirements inside the same document

If something looks uncertain, the pipeline prefers to flag it for review rather than force a confident answer.

## Framework mapping

The codebase includes a curated control catalog for common cybersecurity frameworks, including NIST CSF 2.0 and CIS Controls. The mapping layer uses that catalog to connect extracted requirements to relevant controls when a safe match exists.

This is not a generic auto-classifier. It is a controlled mapping system designed to be traceable, reviewable, and conservative about unsupported matches.

## Terminal experience

The CLI output is deliberately polished so the run is easier to read in a terminal.

It shows:

- a short banner at startup
- progress steps while the pipeline runs
- a run snapshot with icon-based status rows
- a boxed requirements table with confidence and review indicators
- export consistency feedback at the end

That terminal presentation is meant to make the output easier to scan during iterative review sessions.

## Supported output location

By default, generated files are written to a timestamped folder under:

```text
%USERPROFILE%\Documents\ComplianceAgentOutputs
```

If `COMPLIANCE_AGENT_OUTPUT_DIR` is set, the agent uses that location instead.

## Testing and development

The repository includes a small but meaningful automated test suite. It covers pipeline behavior, export consistency, and evaluation metrics.

Run tests with:

```powershell
python -m pytest
```

## Troubleshooting

If setup or execution fails:

1. Confirm `python --version` works and points to the expected interpreter.
2. Verify the virtual environment is activated before installing or running the project.
3. Check that `.env` exists and includes a valid `OPENAI_API_KEY`.
4. Make sure `pip install -r requirements.txt` completed successfully.
5. If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
6. If the hosted API returns an auth or quota error, confirm the key and billing status for the provider you are using.
7. If you are using a local or compatible endpoint, set `OPENAI_BASE_URL` to the correct URL and keep the model name compatible with that provider.

## Why this repository exists

The goal of the project is to show how a compliance-oriented LLM agent can be built as a real software system rather than a prompt demo. It combines document ingestion, schema enforcement, mapping logic, validation, exports, evaluation, and terminal UX into one workflow that can be run locally and inspected end to end.

That makes it useful both as a prototype and as a foundation for further work on compliance automation, policy interpretation, and control mapping.

## Security notes

- Input documents are treated as untrusted content.
- The extractor instructs the model to ignore prompt-injection attempts inside the document.
- Unsupported framework mappings are rejected and flagged.
- JSON and YAML are regenerated locally from validated objects rather than written directly from raw model output.
- Sensitive policy files can stay on the local machine when a local compatible runtime is used.
- Do not commit the `.env` file or paste live API keys into code, chat, or documentation.
