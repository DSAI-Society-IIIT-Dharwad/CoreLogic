"""Blast radius analysis"""
from typing import Dict, List, Any
from core.algorithms import SecurityAlgorithms
from core.graph_engine import KubernetesGraphEngine

class BlastRadiusAnalyzer:
    """Analyzes blast radius for compromised nodes using BFS"""
    
    def __init__(self, graph_engine: KubernetesGraphEngine):
        self.graph_engine = graph_engine
        self.algorithms = SecurityAlgorithms(
            graph_engine.graph,
            graph_engine.node_metadata
        )
    
    def analyze_node_blast_radius(self, node_id: str, max_hops: int = 3) -> Dict[str, Any]:
        """
        Analyze blast radius from a specific node using BFS.
        Returns data matching expected output format.
        """
        if max_hops is None:
            max_hops = 3
            
        result = self.algorithms.blast_radius_bfs(node_id, max_hops)
        
        if "error" in result:
            return result
        
        reachable = result.get("reachable_nodes", [])
        
        # Group by type
        by_type = {}
        for node in reachable:
            node_type = node.get("type", "Unknown")
            if node_type not in by_type:
                by_type[node_type] = []
            by_type[node_type].append(node)
        
        # Group by risk level
        by_risk = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for node in reachable:
            risk = node.get("risk_score", 0)
            if risk >= 9:
                by_risk["CRITICAL"].append(node)
            elif risk >= 7:
                by_risk["HIGH"].append(node)
            elif risk >= 4:
                by_risk["MEDIUM"].append(node)
            else:
                by_risk["LOW"].append(node)
        
        result["breakdown_by_type"] = {k: len(v) for k, v in by_type.items()}
        result["breakdown_by_risk"] = {k: len(v) for k, v in by_risk.items()}
        result["high_risk_nodes"] = by_risk["CRITICAL"] + by_risk["HIGH"]
        
        return result
    
    def analyze_all_sources(self, max_hops: int = 3) -> List[Dict[str, Any]]:
        """
        Analyze blast radius for all source nodes.
        Returns data matching expected output format for Section 2.
        """
        sources = [
            n for n, m in self.graph_engine.node_metadata.items()
            if m.get("is_source") or m.get("is_entry_point")
        ]
        
        results = []
        for source_id in sources:
            result = self.analyze_node_blast_radius(source_id, max_hops)
            if "error" not in result:
                results.append({
                    "source": result.get("source", result.get("start_node_name")),
                    "reachable_resources": result.get("reachable_resources", result.get("total_reachable")),
                    "hops": max_hops,
                    "hop_details": result.get("hop_details", {}),
                })
        
        return results
    
    def compare_blast_radii(self, node_ids: List[str]) -> Dict[str, Any]:
        """Compare blast radii of multiple nodes"""
        comparisons = []
        
        for node_id in node_ids:
            result = self.analyze_node_blast_radius(node_id)
            if "error" not in result:
                comparisons.append({
                    "node_id": node_id,
                    "node_name": result.get("start_node_name"),
                    "total_reachable": result.get("total_reachable"),
                    "crown_jewels_reached": len(result.get("crown_jewels_reached", [])),
                    "severity": result.get("severity"),
                })
        
        comparisons.sort(
            key=lambda x: (x["crown_jewels_reached"], x["total_reachable"]),
            reverse=True
        )
        
        return {
            "nodes_analyzed": len(comparisons),
            "comparisons": comparisons,
            "most_dangerous": comparisons[0] if comparisons else None,
        }
