"""Attack path detection and analysis"""
from typing import Dict, List, Any
from core.algorithms import SecurityAlgorithms
from core.graph_engine import KubernetesGraphEngine

class AttackPathDetector:
    """Detects and analyzes attack paths in Kubernetes clusters"""
    
    def __init__(self, graph_engine: KubernetesGraphEngine):
        self.graph_engine = graph_engine
        self.algorithms = SecurityAlgorithms(
            graph_engine.graph,
            graph_engine.node_metadata
        )
    
    def detect_all_attack_paths(self, max_length: int = 7) -> Dict[str, Any]:
        """
        Detect all possible attack paths using Dijkstra.
        Returns data matching expected output format.
        """
        paths = self.algorithms.dijkstra_attack_paths(max_length)
        
        # Categorize by severity
        categorized = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        
        for path in paths:
            risk_level = path.get("risk_level", "[LOW]")
            # Remove brackets for categorization
            severity_key = risk_level.strip("[]")
            if severity_key in categorized:
                categorized[severity_key].append(path)
        
        # Number the paths
        numbered_paths = []
        for i, path in enumerate(paths, 1):
            path["path_number"] = i
            numbered_paths.append(path)
        
        return {
            "total_paths": len(paths),
            "warning": f"⚠ {len(paths)} attack path(s) detected",
            "by_severity": {
                "critical_count": len(categorized["CRITICAL"]),
                "high_count": len(categorized["HIGH"]),
                "medium_count": len(categorized["MEDIUM"]),
                "low_count": len(categorized["LOW"]),
            },
            "paths": categorized,
            "all_paths": numbered_paths,
            "top_10_critical": numbered_paths[:10],
        }
    
    def find_specific_attack_path(self, source: str, target: str) -> Dict[str, Any]:
        """Find specific attack path between two nodes"""
        return self.algorithms.shortest_attack_path_dijkstra(source, target)
    
    def simulate_attack_from_entry_point(self, entry_point_id: str) -> Dict[str, Any]:
        """Simulate an attack starting from a specific entry point"""
        # Get blast radius with depth 3
        blast_radius = self.algorithms.blast_radius_bfs(entry_point_id, max_hops=3)
        
        # Find paths to crown jewels
        crown_jewels = [
            n for n, m in self.graph_engine.node_metadata.items()
            if m.get("is_crown_jewel") or m.get("is_sink")
        ]
        
        paths_to_jewels = []
        for jewel_id in crown_jewels:
            path_result = self.algorithms.shortest_attack_path_dijkstra(
                entry_point_id, jewel_id
            )
            if path_result.get("path"):
                paths_to_jewels.append(path_result)
        
        return {
            "entry_point": entry_point_id,
            "entry_point_name": self.graph_engine.node_metadata.get(entry_point_id, {}).get("name"),
            "blast_radius": blast_radius,
            "paths_to_crown_jewels": paths_to_jewels,
            "attack_success_probability": self._calculate_success_probability(paths_to_jewels),
        }
    
    def _calculate_success_probability(self, paths: List[Dict]) -> float:
        """Calculate probability of successful attack"""
        if not paths:
            return 0.0
        
        avg_length = sum(p.get("path_length", 10) for p in paths) / len(paths)
        
        if avg_length <= 3:
            return 0.95
        elif avg_length <= 5:
            return 0.75
        elif avg_length <= 7:
            return 0.50
        else:
            return 0.25
