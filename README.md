# repo-sentinel

Repository intelligence and security remediation prototype for analyzing public GitHub repositories, correlating vulnerability intelligence, and producing an executive report.

This is a hackathon prototype. Some paths use simulated findings or demo responses, and the project currently has two partially independent execution surfaces: a browser/API prototype and a command-line LangGraph pipeline.

## Features

- GitHub repository metadata and commit-history intake
- Iterative gap analysis using a Featherless AI model
- CVE enrichment through NVD, FIRST EPSS, and CISA KEV data sources
- Risk scoring and knowledge-graph generation
- Security finding correlation and remediation suggestions
- Correction-agent output for vulnerable source files
- PDF remediation report generation with WeasyPrint
- Browser workflow UI with simulated/live-agent modes

## Architecture

```text
GitHub repository
    |
    v
Repository intake --> LangGraph orchestrator --> Gap analysis loop
                  |                       |
                  v                       v
              CVE enrichment          Risk scoring
                  |                       |
                  +----------+------------+
                          v
                      Knowledge graph
                          |
                          v
                      PDF dossier
```

Important entry points:

| File | Purpose |
| --- | --- |
| `main.py` | CLI entry point for the LangGraph investigation and PDF report pipeline |
| `app.py` | FastAPI prototype endpoint at `POST /api/analyze` |
| `index.html` | Browser dashboard for the API/workflow prototype |
| `compiler/prototype2.html` | More complete standalone workflow UI with simulation and Featherless settings |
| `agents/orchestrator.py` | LangGraph state machine and iterative analysis loop |
| `agents/pdf_builder.py` | HTML-to-PDF report generation |
| `agents/correction_agent.py` | AI-assisted source correction workflow |
| `modules/cve_client.py` | CVE data enrichment client |
| `graph/risk_scorer.py` | Composite risk evaluation |
| `graph/knowledge_graph.py` | Relationship graph construction |

## Requirements

- Python 3.10 or newer
- A virtual environment is recommended
- Featherless AI API access for live LLM analysis
- Internet access for GitHub and CVE data requests
- WeasyPrint system libraries on Windows when generating PDFs

The repository does not currently include a pinned `requirements.txt`. Install the packages used by the current codebase with:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn pydantic pydantic-settings httpx langgraph weasyprint networkx
```

If PowerShell blocks activation, run the commands from an activated terminal or use the equivalent activation command for your shell.

## Configuration

Create a `.env` file in the repository root:

```env
FEATHERLESS_API_KEY=your_api_key_here
FEATHERLESS_ENDPOINT=https://api.featherless.ai/v1/chat/completions
MODEL_NAME=moonshotai/Kimi-K2.5
WEASYPRINT_DLL_DIRECTORIES=C:\msys64\mingw64\bin
```

Never commit API keys. The current `config.py` contains a fallback key value for the prototype; rotate that credential and replace it with an empty or environment-only default before sharing or deploying the repository.

## Run the CLI pipeline

Generate a PDF dossier for a repository target:

```powershell
python main.py --target owner/repository
```

Optional arguments:

```powershell
python main.py --target owner/repository --depth 5 --output reports\repository-dossier.pdf
```

The CLI runs the asynchronous LangGraph workflow, enriches any discovered CVEs, calculates risk data, and writes a PDF report. The default output name is `threat_dossier_<owner>_<repository>.pdf`.

## Run the FastAPI prototype

Start the API:

```powershell
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

The prototype endpoint is:

```text
POST http://127.0.0.1:8000/api/analyze
```

Example request:

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:8000/api/analyze `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"repo_url":"https://github.com/owner/repository","branch":"main","depth":"standard"}'
```

Open `index.html` in a browser to view the companion prototype UI. Its current API response is demo-oriented and returns a synthetic SQL-injection scenario rather than fully analyzing the submitted repository.

## Use the standalone workflow UI

Open `compiler/prototype2.html` directly in a browser. It can run in simulation mode without a Featherless key, using live GitHub metadata where available. To enable live agent calls, configure the Featherless key through the UI settings dialog.

The standalone page is intentionally self-contained and loads Tailwind CSS, Lucide icons, and fonts from CDNs.

## Tests and checks

Run the available test scripts with:

```powershell
python -m pytest
```

The current test files are integration-style scripts:

- `test_correction.py` exercises the correction agent against `vulnerable_app.py` and writes `correction.txt`.
- `test_pdf_report.py` exercises PDF generation and writes `final_remediation_report.pdf`.

These scripts may call external services depending on the configured agent implementation. They are useful smoke checks, but the project does not yet have comprehensive isolated unit-test coverage.

## Safety and limitations

- Treat all AI-generated findings and patches as recommendations requiring human review.
- The CLI pipeline may call external GitHub, CVE, and Featherless services.
- The FastAPI prototype enables permissive CORS and should not be deployed unchanged.
- The browser UI stores configured credentials in browser `localStorage`; use it only for local demonstrations.
- The browser/API prototype and CLI pipeline are not yet a single fully integrated production workflow.
- Generated corrections and reports can overwrite or create local files; review the output paths before running automation.

## Repository workflow

1. Submit a GitHub repository target.
2. Fetch repository metadata and recent commits.
3. Evaluate information gaps with the configured LLM.
4. Enrich discovered CVE identifiers.
5. Score the target and construct a knowledge graph.
6. Generate remediation artifacts and an executive PDF dossier.
7. Review all findings and proposed changes before applying them to a real repository.

## Roadmap

- Add a pinned dependency file and reproducible setup script.
- Remove hardcoded credentials and require environment-based secrets.
- Connect the browser UI to the real orchestrator instead of demo responses.
- Add structured unit tests with mocked GitHub, CVE, and LLM clients.
- Add authentication, restrictive CORS, request validation, and rate limiting to the API.
- Make correction and report output directories configurable.