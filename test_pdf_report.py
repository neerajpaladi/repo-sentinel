import sys
from pathlib import Path

# Add root folder to module search path
sys.path.append(str(Path(__file__).resolve().parent))

from agents.pdf_builder import pdf_builder

original_vulnerable_code = """import sqlite3

def fetch_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Vulnerable to SQL Injection via string interpolation
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()"""

pdf_builder.build_pdf(
    target="Database Module (`fetch_user`)",
    risk_score=10.0,
    vulnerability_title="CWE-89: SQL Injection",
    original_code=original_vulnerable_code,
    correction_file_path="correction.txt",
    output_pdf_path="final_remediation_report.pdf",
    model_used="Kimi 2.5 (Featherless AI)",
    agent_sequence=["github_analyzer", "CorrectionAgent", "PDFBuilder"]
)