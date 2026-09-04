# modules/github_analyzer.py

import os
import httpx
from typing import List, Dict, Any, Optional

GITHUB_API_BASE = "https://api.github.com"

class GitHubAnalyzer:
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    async def fetch_repo_metadata(self, owner_repo: str) -> Dict[str, Any]:
        """Extracts repository overview, star count, primary language, and default branch."""
        url = f"{GITHUB_API_BASE}/repos/{owner_repo}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "full_name": data.get("full_name"),
                        "description": data.get("description"),
                        "stars": data.get("stargazers_count"),
                        "language": data.get("language"),
                        "open_issues": data.get("open_issues_count"),
                        "default_branch": data.get("default_branch")
                    }
            except Exception:
                pass
        return {}

    async def fetch_recent_commits(self, owner_repo: str, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetches recent commits and flags keywords matching patches or security concerns."""
        url = f"{GITHUB_API_BASE}/repos/{owner_repo}/commits"
        suspicious_keywords = ["fix", "patch", "vuln", "secret", "key", "password", "security", "cve"]
        commits = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(url, headers=self.headers, params={"per_page": limit})
                if response.status_code == 200:
                    for commit in response.json():
                        msg = commit.get("commit", {}).get("message", "")
                        author = commit.get("commit", {}).get("author", {}).get("email", "unknown")
                        
                        is_flagged = any(kw in msg.lower() for kw in suspicious_keywords)

                        commits.append({
                            "sha": commit.get("sha", "")[:7],
                            "author_email": author,
                            "message": msg.split("\n")[0] if msg else "",
                            "is_security_relevant": is_flagged,
                            "url": commit.get("html_url", "")
                        })
            except Exception:
                pass
        return commits

github_analyzer = GitHubAnalyzer()