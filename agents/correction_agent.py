# agents/correction_agent.py

import os
import re
import sys
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class CorrectionAgent:
    def __init__(self):
        self.api_key = config.settings.FEATHERLESS_API_KEY
        self.endpoint = config.settings.FEATHERLESS_ENDPOINT
        self.model = config.settings.MODEL_NAME

    def _clean_code_response(self, raw_text: str) -> str:
        """Strips markdown code fences from LLM responses."""
        cleaned = re.sub(r"^```[a-zA-Z]*\n", "", raw_text.strip(), flags=re.MULTILINE)
        cleaned = re.sub(r"\n```$", "", cleaned.strip(), flags=re.MULTILINE)
        return cleaned.strip()

    def refactor_file(
        self,
        source_file_path: str,
        flaws_summary: str,
        output_path: str = "correction.txt"
    ) -> str:
        """
        Reads a repository source file, sends it to Kimi 2.5 with detected flaws,
        and writes the entire refactored code to output_path (default: correction.txt).
        """
        if not os.path.exists(source_file_path):
            print(f"[ERROR] Source file not found: {source_file_path}")
            return ""

        with open(source_file_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        prompt = f"""
You are an expert security engineer and code refactoring system.
Refactor the following complete file to fix all security vulnerabilities, logic mistakes, and code defects.

=== SOURCE FILE ===
{source_file_path}

=== IDENTIFIED FLAWS / MISTAKES ===
{flaws_summary}

=== ORIGINAL CONTENT ===
{original_code}

Task:
1. Completely rewrite the file to correct all reported issues and security flaws.
2. Maintain full compatibility with the existing module interface.
3. Return ONLY the complete, corrected code content without explanations or markdown formatting.
"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }

        try:
            response = requests.post(self.endpoint, headers=headers, json=payload, timeout=60)
            if response.status_code == 200:
                raw_reply = response.json()["choices"][0]["message"]["content"]
                fixed_code = self._clean_code_response(raw_reply)

                output_dir = os.path.dirname(output_path)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)

                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(fixed_code)

                print(f"[SUCCESS] Refactored file saved to: {output_path}")
                return output_path
            else:
                print(f"[ERROR] API returned {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[ERROR] CorrectionAgent failed: {e}")

        return ""


correction_agent = CorrectionAgent()