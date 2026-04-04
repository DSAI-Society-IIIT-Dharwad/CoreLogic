"""Kill Chain report data aggregation"""
from typing import Dict, Any, List
from datetime import datetime

class KillChainAnalyzer:
    """Aggregates data for Kill Chain reports"""
    
    def __init__(self):
        pass
    
    def prepare_report_data(self, 
                             graph_stats: Dict[str, Any],
                             attack_paths: Dict[str, Any],
                             cve_analysis: Dict[str, Any],
                             critical_nodes: List[Dict[str, Any]],
                             risk_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare comprehensive report data"""
        
        # Extract key metrics
        critical_paths = attack_paths.get("by_severity", {}).get("critical_count", 0)
        high_paths = attack_paths.get("by_severity", {}).get("high_count", 0)
        
        crown_jewels_at_risk = self._count_crown_jewels_at_risk(
            attack_paths.get("top_10_critical", [])
        )
        
        report_data = {
            "report_id": f"REPORT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "cluster_name": "prod-cluster",
            
            # Overall risk
            "risk_level": risk_assessment.get("risk_level", "UNKNOWN"),
            "overall_risk_score": risk_assessment.get("overall_risk_score", 0),
            
            # Key metrics
            "total_attack_paths": attack_paths.get("total_paths", 0),
            "critical_paths": critical_paths,
            "high_paths": high_paths,
            "vulnerable_pods": cve_analysis.get("vulnerable_pods_count", 0),
            "crown_jewels_at_risk": crown_jewels_at_risk,
            
            # Detailed data
            "graph_statistics": graph_stats,
            "attack_paths": attack_paths,
            "cve_analysis": cve_analysis,
            "critical_nodes": critical_nodes,
            
            # Recommendations
            "recommendations": self._generate_prioritized_recommendations(
                attack_paths, cve_analysis, critical_nodes
            ),
        }
        
        return report_data
    
    def _count_crown_jewels_at_risk(self, top_paths: List[Dict]) -> int:
        """Count unique crown jewels accessible via attack paths"""
        crown_jewels = set()
        for path in top_paths:
            if path.get("crown_jewel"):
                crown_jewels.add(path["crown_jewel"])
        return len(crown_jewels)
    
    def _generate_prioritized_recommendations(self,
                                               attack_paths: Dict,
                                               cve_analysis: Dict,
                                               critical_nodes: List[Dict]) -> List[Dict]:
        """Generate prioritized list of recommendations"""
        recommendations = []
        priority = 1
        
        # Critical attack paths
        critical_count = attack_paths.get("by_severity", {}).get("critical_count", 0)
        if critical_count > 0:
            recommendations.append({
                "priority": priority,
                "severity": "CRITICAL",
                "action": f"Block {critical_count} critical attack path(s) immediately",
                "impact": "Prevents direct access to crown jewel resources",
            })
            priority += 1
        
        # CVE vulnerabilities
        critical_cves = cve_analysis.get("severity_distribution", {}).get("CRITICAL", 0)
        if critical_cves > 0:
            recommendations.append({
                "priority": priority,
                "severity": "CRITICAL",
                "action": f"Patch {critical_cves} pod(s) with critical CVEs",
                "impact": "Eliminates known exploit vectors",
            })
            priority += 1
        
        # Critical nodes
        if critical_nodes:
            top_node = critical_nodes[0]
            recommendations.append({
                "priority": priority,
                "severity": "HIGH",
                "action": f"Restrict permissions for {top_node.get('name')} ({top_node.get('type')})",
                "impact": f"Breaks {top_node.get('paths_broken', 0)} attack paths",
            })
            priority += 1
        
        # General recommendations
        recommendations.append({
            "priority": priority,
            "severity": "MEDIUM",
            "action": "Implement Network Policies to segment workloads",
            "impact": "Reduces lateral movement capabilities",
        })
        priority += 1
        
        recommendations.append({
            "priority": priority,
            "severity": "MEDIUM",
            "action": "Enable Pod Security Standards (restricted profile)",
            "impact": "Prevents privilege escalation via pod specs",
        })
        
        return recommendations
