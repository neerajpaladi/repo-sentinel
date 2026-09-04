# agents/orchestrator.py

from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from agents.reasoning import evaluate_data_gaps


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
    """Node 1: Fetches baseline repository metadata, commit logs, and preliminary CVEs.
    
    (Note: Hardcoded placeholders below will be replaced by calls to modules/ standard code).
    """
    target = state["target"]
    
    # Placeholder baseline data (will connect to modules/cve_client.py & modules/github_analyzer.py)
    sample_cves = [
        {"id": "CVE-2023-38606", "severity": "CRITICAL", "summary": "Buffer overflow in target dependency."}
    ]
    sample_commits = [
        {"sha": "a1b2c3d", "message": "fix: update vulnerable parser", "author": "dev@target.com"}
    ]

    return {
        "raw_cves": sample_cves,
        "commits": sample_commits,
        "iteration": state["iteration"] + 1,
    }


async def analyze_gaps_node(state: DossierState) -> Dict[str, Any]:
    """Node 2: Uses Kimi 2.5 via Featherless AI to evaluate data completeness."""
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
    """Node 3: Resolves gaps identified by Kimi 2.5 by executing targeted tools."""
    gaps = state.get("missing_gaps", [])
    updated_cves = list(state.get("raw_cves", []))

    for gap in gaps:
        if "CVE" in gap:
            for cve in updated_cves:
                if cve["id"] in gap:
                    cve["poc_found"] = True
                    cve["poc_url"] = f"https://github.com/exploit-db/{cve['id']}"

    return {
        "raw_cves": updated_cves,
        "iteration": state["iteration"] + 1,
    }


async def synthesize_report_node(state: DossierState) -> Dict[str, Any]:
    """Node 4: Compiles all enriched state data into the final dossier payload."""
    report = {
        "target": state["target"],
        "iterations_completed": state["iteration"],
        "cves_identified": state["raw_cves"],
        "commits_analyzed": state["commits"],
        "status": "COMPLETE",
    }
    return {"final_report": report}


def route_next_step(state: DossierState) -> str:
    """Conditional edge router."""
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

    # 2. Wire Fixed Edges
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
    """Asynchronous public entry point to trigger the state machine from main.py."""
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