# agents/reasoning.py

import json
from agents.llm_client import featherless_client

async def evaluate_data_gaps(target: str, raw_cves: list, commits: list) -> list[str]:
    """Uses Kimi 2.5 on Featherless AI to identify missing security context."""
    prompt = f"""Target: {target}
Collected CVEs: {json.dumps(raw_cves)}
Recent Commits: {json.dumps(commits)}

Identify missing critical threat context (e.g., missing exploit PoCs, missing EPSS scores, unmapped contributor emails).
Return ONLY a raw JSON array of targeted action strings.
Example output format: ["Search public PoC for CVE-2023-1234", "Verify commit 4a8b1c for credential leaks"]"""

    messages = [
        {"role": "system", "content": "You are an automated threat intelligence officer. Output strict JSON only."},
        {"role": "user", "content": prompt}
    ]

    response = await featherless_client.generate(messages=messages, temperature=0.2)
    
    try:
        gaps = json.loads(response)
        return gaps if isinstance(gaps, list) else []
    except json.JSONDecodeError:
        return []