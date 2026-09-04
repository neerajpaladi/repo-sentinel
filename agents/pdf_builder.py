import os
import sys
from typing import List, Union
from weasyprint import HTML

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class PDFBuilder:
    def __init__(self):
        pass

    def build_pdf(
        self,
        target: str = "Database Module (`fetch_user`)",
        risk_score: float = 10.0,
        vulnerability_title: str = "CWE-89: SQL Injection",
        original_code: str = "",
        correction_file_path: str = "correction.txt",
        output_pdf_path: str = "final_remediation_report.pdf",
        model_used: str = "Kimi 2.5 (Featherless AI)",
        agent_sequence: Union[List[str], str] = None,
        **kwargs,
    ) -> str:
        target = kwargs.get("target_file", kwargs.get("repo", target))
        risk_score = kwargs.get("score", kwargs.get("risk", risk_score))
        original_code = kwargs.get("code", original_code)

        if agent_sequence is None:
            agent_sequence = kwargs.get(
                "sequence", ["github_analyzer", "CorrectionAgent", "PDFBuilder"]
            )

        formatted_sequence = (
            " ➔ ".join(agent_sequence)
            if isinstance(agent_sequence, list)
            else str(agent_sequence)
        )

        corrected_code = "# Correction file not found."
        if os.path.exists(correction_file_path):
            with open(correction_file_path, "r", encoding="utf-8") as f:
                corrected_code = f.read()

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        @page {{ size: A4; margin: 12mm; background-color: #f8fafc; }}
        body {{ font-family: sans-serif; color: #1e293b; font-size: 10pt; line-height: 1.4; margin: 0; }}
        .header-banner {{ background-color: #0f172a; color: #ffffff; padding: 16px; border-radius: 6px; margin-bottom: 16px; }}
        .header-banner h1 {{ font-size: 16pt; margin: 0 0 4px 0; color: #38bdf8; }}
        .meta-table {{ width: 100%; margin-top: 10px; border-collapse: collapse; }}
        .meta-table td {{ padding: 5px 8px; font-size: 9pt; background-color: #1e293b; color: #e2e8f0; border: 1px solid #334155; }}
        .meta-table .label {{ font-weight: bold; color: #94a3b8; width: 25%; }}
        .badge-critical {{ background-color: #991b1b; color: #ffffff; padding: 2px 6px; border-radius: 4px; font-weight: bold; }}
        .badge-success {{ background-color: #166534; color: #ffffff; padding: 2px 6px; border-radius: 4px; font-weight: bold; }}
        .sequence-box {{ background-color: #0f172a; color: #38bdf8; font-family: monospace; font-size: 9pt; padding: 8px 12px; border-radius: 4px; border: 1px solid #334155; font-weight: bold; }}
        h2 {{ font-size: 12pt; color: #0f172a; border-left: 4px solid #0284c7; padding-left: 8px; margin-top: 16px; margin-bottom: 8px; }}
        .code-container {{ background-color: #0f172a; border-radius: 6px; padding: 10px; margin-bottom: 12px; border: 1px solid #1e293b; }}
        .code-header {{ font-size: 9pt; font-weight: bold; color: #f87171; margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px solid #334155; }}
        .code-header.success {{ color: #4ade80; }}
        pre {{ font-family: monospace; font-size: 8.5pt; color: #f8fafc; margin: 0; white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <div class="header-banner">
        <h1>OSINT Threat Intelligence & Code Remediation Report</h1>
        <div style="color: #94a3b8; font-size: 9pt;">Autonomous Agent Refactoring Pipeline</div>
        <table class="meta-table">
            <tr>
                <td class="label">Target System:</td><td>{target}</td>
                <td class="label">Risk Score:</td><td><span class="badge-critical">{risk_score} / 10</span></td>
            </tr>
            <tr>
                <td class="label">Vulnerability:</td><td>{vulnerability_title}</td>
                <td class="label">Status:</td><td><span class="badge-success">FIXED ({correction_file_path})</span></td>
            </tr>
            <tr>
                <td class="label">AI Model Used:</td><td>{model_used}</td>
                <td class="label">Output File:</td><td>{output_pdf_path}</td>
            </tr>
        </table>
    </div>

    <h2>1. Agent Execution Sequence</h2>
    <div class="sequence-box">{formatted_sequence}</div>

    <h2>2. Original Vulnerable Code</h2>
    <div class="code-container">
        <div class="code-header">Vulnerable Source File</div>
        <pre>{original_code if original_code else "# No original code supplied"}</pre>
    </div>

    <h2>3. Corrected Code Output (`{correction_file_path}`)</h2>
    <div class="code-container">
        <div class="code-header success">Refactored Implementation</div>
        <pre>{corrected_code}</pre>
    </div>
</body>
</html>"""

        # Fast PDF generation (bypasses network latency)
        HTML(string=html_content, url_fetcher=lambda url: None).write_pdf(output_pdf_path)
        print(f"[SUCCESS] PDF Generated: {output_pdf_path}")
        return output_pdf_path

    build_report = build_pdf
    build_remediation_report = build_pdf

pdf_builder = PDFBuilder()