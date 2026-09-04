# test_correction.py
import os
from agents.correction_agent import correction_agent

# Create a temporary sample file to simulate a target repo file
sample_file = "vulnerable_app.py"
with open(sample_file, "w", encoding="utf-8") as f:
    f.write('''import sqlite3

def fetch_user(username):
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
return cursor.fetchone()
''')

flaws = "Critical SQL injection in raw query formatting."

print("[*] Running CorrectionAgent...")
# Refactors vulnerable_app.py and saves the full corrected repository code to correction.txt
correction_agent.refactor_file(
    source_file_path=sample_file,
    flaws_summary=flaws,
    output_path="correction.txt"
)