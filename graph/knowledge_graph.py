# graph/knowledge_graph.py

import networkx as nx
from typing import Dict, Any, List

class ThreatKnowledgeGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, target: str, commits: List[Dict[str, Any]], cves: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Constructs an in-memory directed graph connecting OSINT entities."""
        self.graph.clear()

        # Add central target node
        self.graph.add_node(target, type="Target")

        # Map Commits and Developer relationships
        for commit in commits:
            sha = commit.get("sha")
            author = commit.get("author_email", "unknown")
            if sha:
                self.graph.add_node(sha, type="Commit", message=commit.get("message", ""))
                self.graph.add_edge(target, sha, relation="HAS_COMMIT")

                if author != "unknown":
                    self.graph.add_node(author, type="Developer")
                    self.graph.add_edge(sha, author, relation="AUTHORED_BY")

        # Map Vulnerability relationships
        for cve in cves:
            cve_id = cve.get("cve_id")
            if cve_id:
                self.graph.add_node(
                    cve_id,
                    type="Vulnerability",
                    severity=cve.get("severity", "UNKNOWN"),
                    cvss=cve.get("cvss_score", 0.0)
                )
                self.graph.add_edge(target, cve_id, relation="AFFECTED_BY")

        return self.export_summary()

    def export_summary(self) -> Dict[str, Any]:
        """Exports graph statistics and edge metrics for reporting and PDF rendering."""
        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "developers_identified": [
                node for node, attr in self.graph.nodes(data=True) if attr.get("type") == "Developer"
            ],
            "vulnerabilities_linked": [
                node for node, attr in self.graph.nodes(data=True) if attr.get("type") == "Vulnerability"
            ],
            "adjacency_list": nx.node_link_data(self.graph)
        }

knowledge_graph = ThreatKnowledgeGraph()