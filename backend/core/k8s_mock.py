"""Mock Kubernetes cluster data loader from JSON file"""
import json
import os
from typing import Dict, List, Any
from datetime import datetime

# CVE database for reference
CVE_DATABASE = {
    "CVE-2024-1234": {"cve_id": "CVE-2024-1234", "cvss_score": 8.1, "severity": "HIGH"},
    "CVE-2023-4567": {"cve_id": "CVE-2023-4567", "cvss_score": 7.2, "severity": "HIGH"},
    "CVE-2024-9999": {"cve_id": "CVE-2024-9999", "cvss_score": 6.5, "severity": "MEDIUM"},
    "CVE-2024-3116": {"cve_id": "CVE-2024-3116", "cvss_score": 9.0, "severity": "CRITICAL"},
}

def load_cluster_graph_from_file(filepath: str = None) -> Dict[str, Any]:
    """Load cluster graph from JSON file"""
    if filepath is None:
        # Default path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        filepath = os.path.join(base_dir, "data", "mock-cluster-graph.json")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    return data

def generate_mock_cluster() -> Dict[str, Any]:
    """Generate cluster data from the mock-cluster-graph.json file"""
    raw_data = load_cluster_graph_from_file()
    
    # Build lookup maps
    nodes_by_id = {node["id"]: node for node in raw_data["nodes"]}
    
    # Process nodes into categorized lists
    pods = []
    service_accounts = []
    roles = []
    secrets = []
    services = []
    other_nodes = []
    
    for node in raw_data["nodes"]:
        node_type = node["type"]
        
        # Build CVE info if present
        cve_info = None
        if node.get("cves"):
            cve_id = node["cves"][0] if isinstance(node["cves"], list) and node["cves"] else None
            if cve_id and cve_id in CVE_DATABASE:
                cve_info = CVE_DATABASE[cve_id]
        
        base_node = {
            "id": node["id"],
            "name": node["name"],
            "namespace": node.get("namespace", "default"),
            "type": node_type,
            "risk_score": node.get("risk_score", 0),
            "is_source": node.get("is_source", False),
            "is_sink": node.get("is_sink", False),
            "cves": node.get("cves", []),
        }
        
        if node_type == "Pod":
            pods.append({
                **base_node,
                "exposed_to_internet": node.get("is_source", False),
                "is_privileged": False,
                "cve": cve_info,
                "image": "custom:latest",
            })
        elif node_type == "ServiceAccount":
            service_accounts.append({
                **base_node,
                "auto_mount_token": True,
            })
        elif node_type in ["Role", "ClusterRole"]:
            risk_level = "CRITICAL" if node.get("risk_score", 0) >= 9 else \
                         "HIGH" if node.get("risk_score", 0) >= 7 else \
                         "MEDIUM" if node.get("risk_score", 0) >= 4 else "LOW"
            roles.append({
                **base_node,
                "permissions": ["*"] if "admin" in node["name"].lower() else ["get", "list"],
                "risk_level": risk_level,
            })
        elif node_type == "Secret":
            sensitivity = "CRITICAL" if node.get("risk_score", 0) >= 9 else \
                          "HIGH" if node.get("risk_score", 0) >= 7 else \
                          "MEDIUM" if node.get("risk_score", 0) >= 4 else "LOW"
            secrets.append({
                **base_node,
                "sensitivity": sensitivity,
                "is_crown_jewel": node.get("is_sink", False) or node.get("risk_score", 0) >= 9,
                "contains": "sensitive data",
            })
        elif node_type == "Service":
            services.append(base_node)
        else:
            other_nodes.append(base_node)
    
    # Process edges into role bindings format
    role_bindings = []
    for edge in raw_data["edges"]:
        source_node = nodes_by_id.get(edge["source"], {})
        target_node = nodes_by_id.get(edge["target"], {})
        
        binding = {
            "id": f"binding-{edge['source']}-{edge['target']}",
            "type": edge.get("relationship", "unknown"),
            "source": edge["source"],
            "source_name": source_node.get("name", edge["source"]),
            "target": edge["target"],
            "target_name": target_node.get("name", edge["target"]),
            "weight": edge.get("weight", 1.0),
            "cve": edge.get("cve"),
            "cvss": edge.get("cvss"),
        }
        role_bindings.append(binding)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "cluster_name": raw_data["metadata"]["cluster"],
        "pods": pods,
        "service_accounts": service_accounts,
        "roles": roles,
        "secrets": secrets,
        "services": services,
        "other_nodes": other_nodes,
        "role_bindings": role_bindings,
        "raw_graph": raw_data,
        "metadata": {
            "total_nodes": raw_data["metadata"]["node_count"],
            "total_edges": raw_data["metadata"]["edge_count"],
            "namespaces": list(set(n.get("namespace", "default") for n in raw_data["nodes"])),
        }
    }


class MockK8sCluster:
    """Wrapper class for compatibility"""
    
    def __init__(self, mode="random", **kwargs):
        self.mode = mode
    
    def generate_cluster_data(self) -> Dict[str, Any]:
        return generate_mock_cluster()
