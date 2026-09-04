# graph/risk_scorer.py

from typing import Dict, Any, List

class RiskScorer:
    @staticmethod
    def calculate_cve_risk(cve: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates a composite risk score for an individual CVE.
        
        Formula:
        Composite = (CVSS * 0.5) + (EPSS_Score * 10 * 0.3) + (KEV_Bonus [2.0 if True else 0.0])
        """
        cvss = float(cve.get("cvss_score", 0.0))
        epss = float(cve.get("epss_score", 0.0))
        is_kev = bool(cve.get("is_cisa_kev", False))

        # Weight components
        cvss_component = cvss * 0.5
        epss_component = (epss * 10.0) * 0.3
        kev_component = 2.0 if is_kev else 0.0

        raw_score = cvss_component + epss_component + kev_component
        composite_score = round(min(10.0, raw_score), 2)

        # Categorize risk level
        if composite_score >= 9.0:
            rating = "CRITICAL"
        elif composite_score >= 7.0:
            rating = "HIGH"
        elif composite_score >= 4.0:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "cve_id": cve.get("cve_id"),
            "composite_score": composite_score,
            "risk_rating": rating,
            "is_cisa_kev": is_kev,
            "epss_probability": epss,
            "cvss_score": cvss
        }

    @classmethod
    def evaluate_target_risk(cls, cves: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregates scores across all identified CVEs to determine overall target risk."""
        if not cves:
            return {"overall_score": 0.0, "overall_rating": "LOW", "cve_breakdown": []}

        scored_cves = [cls.calculate_cve_risk(cve) for cve in cves]
        max_score = max(c["composite_score"] for c in scored_cves)
        
        if max_score >= 9.0:
            overall_rating = "CRITICAL"
        elif max_score >= 7.0:
            overall_rating = "HIGH"
        elif max_score >= 4.0:
            overall_rating = "MEDIUM"
        else:
            overall_rating = "LOW"

        return {
            "overall_score": max_score,
            "overall_rating": overall_rating,
            "cve_breakdown": sorted(scored_cves, key=lambda x: x["composite_score"], reverse=True)
        }

risk_scorer = RiskScorer()