# modules/cve_client.py

import httpx
from typing import Dict, Any, Optional

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class VulnerabilityClient:
    def __init__(self):
        self.headers = {"User-Agent": "OSINT-Dossier-Generator/1.0"}

    async def get_epss_score(self, cve_id: str) -> Dict[str, Any]:
        """Fetches EPSS probability and percentile for a given CVE ID."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(EPSS_API_URL, params={"cve": cve_id}, headers=self.headers)
                if response.status_code == 200:
                    data = response.json().get("data", [])
                    if data:
                        return {
                            "epss_score": float(data[0].get("epss", 0.0)),
                            "percentile": float(data[0].get("percentile", 0.0))
                        }
            except Exception:
                pass
        return {"epss_score": 0.0, "percentile": 0.0}

    async def is_in_cisa_kev(self, cve_id: str) -> bool:
        """Cross-references a CVE against the CISA Known Exploited Vulnerabilities catalog."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(CISA_KEV_URL, headers=self.headers)
                if response.status_code == 200:
                    vulnerabilities = response.json().get("vulnerabilities", [])
                    return any(vuln.get("cveID") == cve_id for vuln in vulnerabilities)
            except Exception:
                pass
        return False

    async def get_nvd_details(self, cve_id: str) -> Dict[str, Any]:
        """Fetches detailed severity, CVSS scores, and descriptions from NIST NVD."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=self.headers)
                if response.status_code == 200:
                    vulnerabilities = response.json().get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_data = vulnerabilities[0].get("cve", {})
                        metrics = cve_data.get("metrics", {})
                        
                        # Extract CVSS v3.1 or v3.0 metrics if available
                        cvss_data = {}
                        if "cvssMetricV31" in metrics:
                            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                        elif "cvssMetricV30" in metrics:
                            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})

                        descriptions = cve_data.get("descriptions", [])
                        summary = descriptions[0].get("value", "") if descriptions else ""

                        return {
                            "cve_id": cve_id,
                            "cvss_score": cvss_data.get("baseScore", 0.0),
                            "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                            "vector_string": cvss_data.get("vectorString", ""),
                            "summary": summary
                        }
            except Exception:
                pass
        return {"cve_id": cve_id, "cvss_score": 0.0, "severity": "UNKNOWN", "vector_string": "", "summary": ""}

    async def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        """Aggregates metrics across NVD, EPSS, and CISA KEV into a single record."""
        nvd_data = await self.get_nvd_details(cve_id)
        epss_data = await self.get_epss_score(cve_id)
        is_kev = await self.is_in_cisa_kev(cve_id)

        nvd_data.update(epss_data)
        nvd_data["is_cisa_kev"] = is_kev
        return nvd_data

cve_client = VulnerabilityClient()