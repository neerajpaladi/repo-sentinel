# compiler/pdf_builder.py

from typing import Dict, Any
from weasyprint import HTML


class PDFDossierBuilder:
    """Generates an executive-ready PDF OSINT Threat Dossier using WeasyPrint."""

    @staticmethod
    def _generate_html(report_data: Dict[str, Any]) -> str:
        target = report_data.get("target", "Unknown Target")
        iterations = report_data.get("iterations_completed", 0)
        risk_info = report_data.get("risk_assessment", {})
        overall_score = risk_info.get("overall_score", 0.0)
        overall_rating = risk_info.get("overall_rating", "LOW")
        cve_breakdown = risk_info.get("cve_breakdown", [])
        
        graph_info = report_data.get("knowledge_graph", {})
        commits = report_data.get("commits_analyzed", [])
        
        # Color themes matching threat priority levels
        rating_colors = {
            "CRITICAL": {"bg": "#fef2f2", "text": "#991b1b", "border": "#f87171", "badge": "#dc2626"},
            "HIGH": {"bg": "#fff7ed", "text": "#9a3412", "border": "#fb923c", "badge": "#ea580c"},
            "MEDIUM": {"bg": "#fefce8", "text": "#854d0e", "border": "#facc15", "badge": "#ca8a04"},
            "LOW": {"bg": "#f0fdf4", "text": "#166534", "border": "#4ade80", "badge": "#16a34a"}
        }
        theme = rating_colors.get(overall_rating, rating_colors["LOW"])

        # Format CVE table rows
        cve_rows_html = ""
        if cve_breakdown:
            for item in cve_breakdown:
                cve_id = item.get("cve_id", "N/A")
                score = item.get("composite_score", 0.0)
                cvss = item.get("cvss_score", 0.0)
                epss_pct = round(item.get("epss_probability", 0.0) * 100, 2)
                is_kev = item.get("is_cisa_kev", False)
                rating = item.get("risk_rating", "LOW")

                badge_color = rating_colors.get(rating, rating_colors["LOW"])["badge"]
                kev_badge = '<span class="badge badge-kev">KEV ACTIVE</span>' if is_kev else '<span class="badge badge-none">No KEV</span>'

                cve_rows_html += f"""
                <tr>
                    <td class="font-mono"><strong>{cve_id}</strong></td>
                    <td><span class="badge" style="background-color: {badge_color}; color: #ffffff;">{rating} ({score})</span></td>
                    <td>{cvss}</td>
                    <td>{epss_pct}%</td>
                    <td>{kev_badge}</td>
                </tr>
                """
        else:
            cve_rows_html = '<tr><td colspan="5" class="text-center">No vulnerabilities detected.</td></tr>'

        # Format Commit table rows
        commit_rows_html = ""
        if commits:
            for c in commits[:10]:  # Display top 10 commits
                sha = c.get("sha", "N/A")
                author = c.get("author_email", "unknown")
                msg = c.get("message", "")
                flagged = c.get("is_security_relevant", False)

                flag_badge = '<span class="badge badge-flagged">SEC RELEVANT</span>' if flagged else '<span class="badge badge-normal">STANDARD</span>'

                commit_rows_html += f"""
                <tr>
                    <td class="font-mono">{sha}</td>
                    <td>{author}</td>
                    <td>{msg[:60]}{"..." if len(msg) > 60 else ""}</td>
                    <td>{flag_badge}</td>
                </tr>
                """
        else:
            commit_rows_html = '<tr><td colspan="4" class="text-center">No commit logs retrieved.</td></tr>'

        devs = graph_info.get("developers_identified", [])
        devs_str = ", ".join(devs) if devs else "None identified"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OSINT Threat Dossier - {target}</title>
    <style>
        @page {{
            size: A4;
            margin: 15mm 12mm;
            background-color: #f8fafc;
            @bottom-right {{
                content: "Page " counter(page) " of " counter(pages);
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
            }}
            @bottom-left {{
                content: "CONFIDENTIAL // OSINT INTELLIGENCE DOSSIER";
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 8pt;
                color: #64748b;
                font-weight: bold;
            }}
        }}

        *, *::before, *::after {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family: 'Helvetica Neue', Arial, sans-serif;
            color: #1e293b;
            font-size: 9.5pt;
            line-height: 1.5;
        }}

        .banner {{
            background-color: #0f172a;
            color: #ffffff;
            padding: 20px 18px;
            margin: -15mm -12mm 15px -12mm;
            border-bottom: 4px solid {theme["badge"]};
        }}

        .banner table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .banner h1 {{
            margin: 0 0 4px 0;
            font-size: 18pt;
            color: #f8fafc;
        }}

        .banner .subtitle {{
            margin: 0;
            font-size: 9pt;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .banner .meta-right {{
            text-align: right;
            vertical-align: middle;
            font-size: 8.5pt;
            color: #cbd5e1;
        }}

        .metrics-container {{
            width: 100%;
            margin-bottom: 15px;
            border-collapse: separate;
            border-spacing: 8px 0;
        }}

        .metric-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 10px 12px;
            text-align: center;
        }}

        .metric-card .val {{
            font-size: 16pt;
            font-weight: bold;
            color: #0f172a;
        }}

        .metric-card .lbl {{
            font-size: 7.5pt;
            color: #64748b;
            text-transform: uppercase;
            margin-top: 4px;
        }}

        h2 {{
            font-size: 12pt;
            color: #0f172a;
            border-left: 4px solid #2563eb;
            padding-left: 8px;
            margin: 16px 0 10px 0;
            page-break-after: avoid;
        }}

        .risk-callout {{
            background-color: {theme["bg"]};
            border: 1px solid {theme["border"]};
            border-left: 5px solid {theme["badge"]};
            padding: 12px 15px;
            margin-bottom: 15px;
            border-radius: 4px;
            page-break-inside: avoid;
        }}

        .risk-callout table {{
            width: 100%;
        }}

        .risk-callout .risk-score {{
            font-size: 22pt;
            font-weight: bold;
            color: {theme["text"]};
        }}

        .risk-callout .risk-label {{
            font-size: 9pt;
            font-weight: bold;
            color: {theme["text"]};
            text-transform: uppercase;
        }}

        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            margin-bottom: 15px;
            font-size: 9pt;
        }}

        table.data-table th {{
            background-color: #1e293b;
            color: #ffffff;
            text-align: left;
            padding: 7px 10px;
            font-size: 8pt;
            text-transform: uppercase;
        }}

        table.data-table td {{
            padding: 7px 10px;
            border-bottom: 1px solid #e2e8f0;
            color: #334155;
            vertical-align: middle;
        }}

        table.data-table tr:nth-child(even) td {{
            background-color: #f8fafc;
        }}

        .badge {{
            display: inline-block;
            padding: 2px 6px;
            font-size: 7.5pt;
            font-weight: bold;
            border-radius: 3px;
            text-transform: uppercase;
        }}

        .badge-kev {{
            background-color: #ef4444;
            color: #ffffff;
        }}

        .badge-none {{
            background-color: #e2e8f0;
            color: #64748b;
        }}

        .badge-flagged {{
            background-color: #f59e0b;
            color: #ffffff;
        }}

        .badge-normal {{
            background-color: #f1f5f9;
            color: #475569;
        }}

        .font-mono {{
            font-family: 'Courier New', Courier, monospace;
            font-size: 8.5pt;
        }}

        .text-center {{
            text-align: center;
        }}

        .kg-box {{
            background-color: #ffffff;
            border: 1px solid #cbd5e1;
            padding: 12px 15px;
            border-radius: 4px;
            margin-bottom: 15px;
            page-break-inside: avoid;
        }}

        .kg-box table {{
            width: 100%;
        }}

        .kg-item {{
            font-size: 8.5pt;
            color: #475569;
        }}

        .footer-note {{
            margin-top: 20px;
            font-size: 8pt;
            color: #94a3b8;
            text-align: center;
            border-top: 1px solid #e2e8f0;
            padding-top: 8px;
        }}
    </style>
</head>
<body>

    <div class="banner">
        <table>
            <tr>
                <td>
                    <p class="subtitle">OSINT Threat Intelligence Dossier</p>
                    <h1>{target}</h1>
                </td>
                <td class="meta-right">
                    <strong>Classification:</strong> CONFIDENTIAL<br>
                    <strong>Iterative Depth:</strong> {iterations} Cycles<br>
                    <strong>Status:</strong> ANALYSIS COMPLETE
                </td>
            </tr>
        </table>
    </div>

    <div class="risk-callout">
        <table>
            <tr>
                <td style="width: 25%; text-align: center; border-right: 1px solid {theme["border"]}; padding-right: 15px;">
                    <div class="risk-score">{overall_score}</div>
                    <div class="risk-label">{overall_rating} RISK</div>
                </td>
                <td style="padding-left: 15px; vertical-align: middle;">
                    <strong style="color: {theme["text"]}; font-size: 10pt;">Executive Summary & Threat Verdict:</strong>
                    <p style="margin: 4px 0 0 0; color: #334155;">
                        Target <strong>{target}</strong> evaluated across OSINT data feeds.
                        Composite threat score reached <strong>{overall_score} / 10.0</strong> ({overall_rating} priority).
                    </p>
                </td>
            </tr>
        </table>
    </div>

    <table class="metrics-container">
        <tr>
            <td class="metric-card" style="width: 25%;">
                <div class="val">{len(cve_breakdown)}</div>
                <div class="lbl">CVEs Identified</div>
            </td>
            <td class="metric-card" style="width: 25%;">
                <div class="val">{len(commits)}</div>
                <div class="lbl">Commits Analyzed</div>
            </td>
            <td class="metric-card" style="width: 25%;">
                <div class="val">{graph_info.get("node_count", 0)}</div>
                <div class="lbl">Graph Entities</div>
            </td>
            <td class="metric-card" style="width: 25%;">
                <div class="val">{graph_info.get("edge_count", 0)}</div>
                <div class="lbl">Entity Relations</div>
            </td>
        </tr>
    </table>

    <h2>Vulnerability Intelligence & Exploit Prediction</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th style="width: 25%;">CVE Reference</th>
                <th style="width: 22%;">Composite Score</th>
                <th style="width: 15%;">CVSS v3</th>
                <th style="width: 18%;">EPSS Prob.</th>
                <th style="width: 20%;">CISA KEV</th>
            </tr>
        </thead>
        <tbody>
            {cve_rows_html}
        </tbody>
    </table>

    <h2>Source Code & Commits Security Analysis</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th style="width: 15%;">Commit SHA</th>
                <th style="width: 28%;">Author Email</th>
                <th style="width: 40%;">Commit Headline</th>
                <th style="width: 17%;">Flag</th>
            </tr>
        </thead>
        <tbody>
            {commit_rows_html}
        </tbody>
    </table>

    <h2>OSINT Knowledge Graph Mapping</h2>
    <div class="kg-box">
        <table>
            <tr>
                <td style="width: 50%; vertical-align: top;" class="kg-item">
                    <strong>Node Summary:</strong><br>
                    &bull; Target Entry: <code>{target}</code><br>
                    &bull; Linked Vulnerabilities: {len(graph_info.get("vulnerabilities_linked", []))}<br>
                    &bull; Total Commits Mapped: {len(commits)}
                </td>
                <td style="width: 50%; vertical-align: top;" class="kg-item">
                    <strong>Developer Contacts Identified:</strong><br>
                    <span style="color: #2563eb;">{devs_str}</span>
                </td>
            </tr>
        </table>
    </div>

    <div class="footer-note">
        Automated Intelligence Report generated via Featherless AI (Kimi 2.5) & LangGraph Orchestrator
    </div>

</body>
</html>
"""

    @classmethod
    def build_pdf(cls, report_data: Dict[str, Any], output_filename: str = "threat_dossier.pdf") -> str:
        """Compiles report payload into HTML and renders a polished PDF file."""
        html_str = cls._generate_html(report_data)
        HTML(string=html_str).write_pdf(target=output_filename)
        return output_filename


pdf_builder = PDFDossierBuilder()