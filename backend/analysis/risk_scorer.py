"""Risk scoring and assessment"""
import os
from typing import Dict, List, Any
from core.graph_engine import KubernetesGraphEngine
from core.cve_scoring import CVEScorer

class RiskScorer:
    """Calculates comprehensive risk scores"""
    
    def __init__(self, graph_engine: KubernetesGraphEngine):
        self.graph_engine = graph_engine
        # Initialize CVE scorer with environment config
        use_live_api = os.getenv("USE_LIVE_CVE_API", "true").lower() == "true"
        nist_api_key = os.getenv("NIST_NVD_API_KEY")
        self.cve_scorer = CVEScorer(use_live_api=use_live_api, api_key=nist_api_key)
    
    def calculate_cluster_risk_score(self, cluster_data: Dict[str, Any], 
                                      attack_paths: List[Dict]) -> Dict[str, Any]:
        """Calculate overall cluster risk score"""
        
        # CVE-based risk
        cve_scan = self.cve_scorer.scan_cluster_vulnerabilities(cluster_data)
        cve_risk = self._calculate_cve_risk(cve_scan)
        
        # Attack path risk
        path_risk = self._calculate_path_risk(attack_paths)
        
        # Configuration risk
        config_risk = self._calculate_config_risk(cluster_data)
        
        # Overall risk (weighted average)
        overall_risk = (cve_risk * 0.4 + path_risk * 0.4 + config_risk * 0.2)
        
        return {
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": self._score_to_level(overall_risk),
            "breakdown": {
                "cve_risk": round(cve_risk, 2),
                "attack_path_risk": round(path_risk, 2),
                "configuration_risk": round(config_risk, 2),
            },
            "cve_details": cve_scan,
            "recommendations": self._generate_risk_recommendations(overall_risk, cve_scan, attack_paths),
        }
    
    def _calculate_cve_risk(self, cve_scan: Dict[str, Any]) -> float:
        """Calculate risk from CVE vulnerabilities"""
        severity_counts = cve_scan.get("severity_distribution", {})
        
        risk = (
            severity_counts.get("CRITICAL", 0) * 10 +
            severity_counts.get("HIGH", 0) * 7 +
            severity_counts.get("MEDIUM", 0) * 4 +
            severity_counts.get("LOW", 0) * 1
        )
        
        # Normalize to 0-10 scale
        return min(risk / 5, 10.0)
    
    def _calculate_path_risk(self, attack_paths: List[Dict]) -> float:
        """Calculate risk from attack paths"""
        if not attack_paths:
            return 0.0
        
        critical_paths = sum(1 for p in attack_paths if p.get("severity") == "CRITICAL")
        high_paths = sum(1 for p in attack_paths if p.get("severity") == "HIGH")
        
        risk = critical_paths * 3 + high_paths * 1.5
        
        # Normalize to 0-10 scale
        return min(risk, 10.0)
    
    def _calculate_config_risk(self, cluster_data: Dict[str, Any]) -> float:
        """Calculate risk from misconfigurations"""
        risk = 0.0
        
        # Check for overly permissive roles
        roles = cluster_data.get("roles", [])
        for role in roles:
            if "*" in role.get("permissions", []):
                risk += 2.0
            if role.get("type") == "ClusterRole" and role.get("risk_level") == "CRITICAL":
                risk += 1.5
        
        # Check for privileged pods
        pods = cluster_data.get("pods", [])
        privileged_count = sum(1 for p in pods if p.get("is_privileged"))
        risk += privileged_count * 0.5
        
        # Check for internet-exposed pods
        exposed_count = sum(1 for p in pods if p.get("exposed_to_internet"))
        risk += exposed_count * 0.7
        
        # Normalize to 0-10 scale
        return min(risk, 10.0)
    
    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to risk level"""
        if score >= 8.0:
            return "CRITICAL"
        elif score >= 6.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_risk_recommendations(self, overall_risk: float, 
                                        cve_scan: Dict, 
                                        attack_paths: List[Dict]) -> List[str]:
        """Generate recommendations based on risk assessment"""
        recommendations = []
        
        if overall_risk >= 8.0:
            recommendations.append("🚨 CRITICAL: Immediate action required to secure cluster")
        
        # CVE recommendations
        vulnerable_count = cve_scan.get("vulnerable_pods_count", 0)
        if vulnerable_count > 0:
            recommendations.append(
                f"Patch {vulnerable_count} vulnerable pod(s) with known CVEs"
            )
        
        # Attack path recommendations
        critical_paths = sum(1 for p in attack_paths if p.get("severity") == "CRITICAL")
        if critical_paths > 0:
            recommendations.append(
                f"Block {critical_paths} critical attack path(s) leading to sensitive resources"
            )
        
        recommendations.append("Implement Network Policies to segment workloads")
        recommendations.append("Apply Pod Security Standards to restrict container privileges")
        recommendations.append("Enable audit logging for RBAC and resource access")
        
        return recommendations
