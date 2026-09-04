# agents/orchestrator.py

import re
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from agents.reasoning import evaluate_data_gaps
from modules.cve_client import cve_client
from modules.github_analyzer import github_analyzer
from graph.risk_scorer import risk_scorer
from graph.knowledge_graph import knowledge_graph


class DossierState(TypedDict):
    """Tracks state across the dynamic threat analysis loop."""
    target: str
    iteration: int
    max_iterations: int
    raw_cves: List[Dict[str, Any]]
    commits: List[Dict[str, Any]]
    missing_gaps: List[str]
    is_complete: bool
    final_report: Dict[str, Any]


async def ingest_target_node(state: DossierState) -> Dict[str, Any]:
    """Node 1: Fetches live target repository metadata and recent commit history."""
    target = state["target"]
    
    # Query GitHub API directly for recent commit history
    commits = await github_analyzer.fetch_recent_commits(target)

    return {
        "commits": commits,
        "iteration": state["iteration"] + 1,
    }


async def analyze_gaps_node(state: DossierState) -> Dict[str, Any]:
    """Node 2: Uses Kimi 2.5 via Featherless AI to evaluate state sufficiency."""
    if state["iteration"] >= state["max_iterations"]:
        return {"missing_gaps": [], "is_complete": True}

    gaps = await evaluate_data_gaps(
        target=state["target"],
        raw_cves=state["raw_cves"],
        commits=state["commits"],
    )

    return {
        "missing_gaps": gaps,
        "is_complete": len(gaps) == 0,
    }


async def execute_subqueries_node(state: DossierState) -> Dict[str, Any]:
    """Node 3: Dynamically parses gaps identified by Kimi 2.5 and fetches live vulnerability intelligence."""
    gaps = state.get("missing_gaps", [])
    current_cves = list(state.get("raw_cves", []))
    existing_cve_ids = {c.get("cve_id") for c in current_cves if "cve_id" in c}

    # Regex pattern to match standard CVE formats (e.g., CVE-2023-38606)
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    for gap in gaps:
        found_cves = cve_pattern.findall(gap)
        for cve_id in found_cves:
            cve_id_upper = cve_id.upper()
            if cve_id_upper not in existing_cve_ids:
                # Fetch aggregated metrics across NVD, FIRST EPSS, and CISA KEV
                enriched_data = await cve_client.enrich_cve(cve_id_upper)
                current_cves.append(enriched_data)
                existing_cve_ids.add(cve_id_upper)

    return {
        "raw_cves": current_cves,
        "iteration": state["iteration"] + 1,
    }


async def synthesize_report_node(state: DossierState) -> Dict[str, Any]:
    """Node 4: Evaluates risk metrics, generates knowledge graph, and outputs final dossier object."""
    # Compute composite CVSS/EPSS/KEV threat scores
    risk_summary = risk_scorer.evaluate_target_risk(state["raw_cves"])
    
    # Map entities into the directed NetworkX graph
    graph_summary = knowledge_graph.build_graph(
        target=state["target"],
        commits=state["commits"],
        cves=state["raw_cves"],
    )

    report = {
        "target": state["target"],
        "iterations_completed": state["iteration"],
        "risk_assessment": risk_summary,
        "knowledge_graph": graph_summary,
        "commits_analyzed": state["commits"],
        "status": "COMPLETE",
    }
    return {"final_report": report}


def route_next_step(state: DossierState) -> str:
    """Conditional edge router determining loop continuation or completion."""
    if state["is_complete"]:
        return "synthesize_report"
    return "execute_subqueries"


def build_orchestrator() -> Any:
    """Constructs and compiles the asynchronous LangGraph state machine."""
    workflow = StateGraph(DossierState)

    # 1. Register Nodes
    workflow.add_node("ingest_target", ingest_target_node)
    workflow.add_node("analyze_gaps", analyze_gaps_node)
    workflow.add_node("execute_subqueries", execute_subqueries_node)
    workflow.add_node("synthesize_report", synthesize_report_node)

    # 2. Wire Entry Point & Fixed Edges
    workflow.set_entry_point("ingest_target")
    workflow.add_edge("ingest_target", "analyze_gaps")

    # 3. Dynamic Conditional Edge
    workflow.add_conditional_edges(
        "analyze_gaps",
        route_next_step,
        {
            "execute_subqueries": "execute_subqueries",
            "synthesize_report": "synthesize_report",
        },
    )

    # 4. Re-evaluation Loop Edge
    workflow.add_edge("execute_subqueries", "analyze_gaps")
    workflow.add_edge("synthesize_report", END)

    return workflow.compile()


async def run_investigation(target: str, max_depth: int = 3) -> Dict[str, Any]:
    """Asynchronous entry point invoked by main.py to start an investigation."""
    graph = build_orchestrator()

    initial_state: DossierState = {
        "target": target,
        "iteration": 0,
        "max_iterations": max_depth,
        "raw_cves": [],
        "commits": [],
        "missing_gaps": [],
        "is_complete": False,
        "final_report": {},
    }

    result = await graph.ainvoke(initial_state)
    return result.get("final_report", {})
# Inside orchestrator.py or your agent graph definition

from agents.correction_agent import correction_agent

def correction_node(state: dict) -> dict:
    original_code = state.get("target_code", "# No code captured")
    flaws = state.get("risk_assessment_summary", "Detected security vulnerabilities.")
    
    # Save the refactored code directly into correction.py
    correction_path = correction_agent.generate_and_save_correction(
        original_code=original_code,
        flaws_summary=flaws,
        output_filename="correction.py"
    )
    
    state["correction_file"] = correction_path
    return state