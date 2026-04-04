"""Core graph engine using NetworkX for DAG construction and analysis"""
import networkx as nx
from typing import Dict, List, Any, Tuple, Optional
import json
from datetime import datetime

# CVE database for edge vulnerabilities
CVE_DATABASE = {
    "CVE-2024-1234": {"cve_id": "CVE-2024-1234", "cvss_score": 8.1, "severity": "HIGH"},
    "CVE-2023-4567": {"cve_id": "CVE-2023-4567", "cvss_score": 7.2, "severity": "HIGH"},
    "CVE-2024-9999": {"cve_id": "CVE-2024-9999", "cvss_score": 6.5, "severity": "MEDIUM"},
    "CVE-2024-3116": {"cve_id": "CVE-2024-3116", "cvss_score": 9.0, "severity": "CRITICAL"},
}


class KubernetesGraphEngine:
    """Builds and manages Kubernetes permission graph as DAG"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_metadata = {}
        self.edge_metadata = {}
        self.id_to_name = {}
        self.name_to_id = {}
        
    def build_graph_from_cluster_data(self, cluster_data: Dict[str, Any]) -> nx.DiGraph:
        """Build NetworkX DAG from Kubernetes cluster data"""
        self.graph.clear()
        self.node_metadata.clear()
        self.edge_metadata.clear()
        self.id_to_name.clear()
        self.name_to_id.clear()
        
        # Check if we have raw_graph data (new format)
        if "raw_graph" in cluster_data:
            return self._build_from_raw_graph(cluster_data["raw_graph"])
        
        # Fallback to old format
        self._add_pod_nodes(cluster_data.get("pods", []))
        self._add_service_account_nodes(cluster_data.get("service_accounts", []))
        self._add_role_nodes(cluster_data.get("roles", []))
        self._add_secret_nodes(cluster_data.get("secrets", []))
        self._add_edges_from_bindings(cluster_data.get("role_bindings", []))
        self._add_role_to_secret_edges(cluster_data)
        
        return self.graph
    
    def _build_from_raw_graph(self, raw_graph: Dict[str, Any]) -> nx.DiGraph:
        """Build graph directly from raw graph JSON structure"""
        # Add all nodes
        for node in raw_graph["nodes"]:
            node_id = node["id"]
            node_name = node["name"]
            
            self.graph.add_node(node_id)
            self.id_to_name[node_id] = node_name
            self.name_to_id[node_name] = node_id
            
            # Build CVE info
            cve_info = None
            if node.get("cves"):
                cve_id = node["cves"][0] if isinstance(node["cves"], list) and node["cves"] else None
                if cve_id and cve_id in CVE_DATABASE:
                    cve_info = CVE_DATABASE[cve_id]
            
            # Determine if this is an entry point (source) or crown jewel (sink)
            is_entry_point = node.get("is_source", False)
            is_crown_jewel = node.get("is_sink", False)
            
            self.node_metadata[node_id] = {
                "id": node_id,
                "name": node_name,
                "type": node["type"],
                "namespace": node.get("namespace", "default"),
                "risk_score": node.get("risk_score", 0),
                "is_entry_point": is_entry_point,
                "is_source": is_entry_point,
                "is_crown_jewel": is_crown_jewel,
                "is_sink": is_crown_jewel,
                "cves": node.get("cves", []),
                "cve": cve_info,
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
        
        # Add all edges
        for edge in raw_graph["edges"]:
            source = edge["source"]
            target = edge["target"]
            
            if source in self.graph and target in self.graph:
                # Get CVE info for edge if present
                edge_cve = None
                if edge.get("cve"):
                    edge_cve = {
                        "cve_id": edge["cve"],
                        "cvss": edge.get("cvss", 0)
                    }
                
                edge_data = {
                    "weight": edge.get("weight", 1.0),
                    "relationship": edge.get("relationship", "unknown"),
                    "binding_type": edge.get("relationship", "unknown"),
                    "cve": edge_cve,
                }
                
                self.graph.add_edge(source, target, **edge_data)
                self.edge_metadata[(source, target)] = edge_data
        
        return self.graph
    
    def _add_pod_nodes(self, pods: List[Dict]):
        """Add pod nodes to graph"""
        for pod in pods:
            node_id = pod["id"]
            self.graph.add_node(node_id)
            
            self.id_to_name[node_id] = pod["name"]
            self.name_to_id[pod["name"]] = node_id
            
            # Calculate risk score for pod
            risk_score = pod.get("risk_score", 0.0)
            if not risk_score:
                if pod.get("exposed_to_internet"):
                    risk_score += 5.0
                if pod.get("is_privileged"):
                    risk_score += 3.0
                if pod.get("cve"):
                    cvss = pod["cve"].get("cvss_score", 0)
                    risk_score += cvss
            
            self.node_metadata[node_id] = {
                "id": node_id,
                "name": pod["name"],
                "type": "Pod",
                "namespace": pod.get("namespace"),
                "image": pod.get("image"),
                "exposed_to_internet": pod.get("exposed_to_internet", False),
                "is_privileged": pod.get("is_privileged", False),
                "cve": pod.get("cve"),
                "cves": pod.get("cves", []),
                "risk_score": risk_score,
                "is_entry_point": pod.get("exposed_to_internet", False) or pod.get("is_source", False),
                "is_source": pod.get("is_source", False),
                "is_sink": pod.get("is_sink", False),
                "is_crown_jewel": pod.get("is_sink", False),
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_service_account_nodes(self, service_accounts: List[Dict]):
        """Add service account nodes to graph"""
        for sa in service_accounts:
            node_id = sa["id"]
            self.graph.add_node(node_id)
            
            self.id_to_name[node_id] = sa["name"]
            self.name_to_id[sa["name"]] = node_id
            
            self.node_metadata[node_id] = {
                "id": node_id,
                "name": sa["name"],
                "type": "ServiceAccount",
                "namespace": sa.get("namespace"),
                "auto_mount_token": sa.get("auto_mount_token", True),
                "risk_score": sa.get("risk_score", 2.0 if sa.get("auto_mount_token") else 1.0),
                "is_entry_point": sa.get("is_source", False),
                "is_crown_jewel": sa.get("is_sink", False),
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_role_nodes(self, roles: List[Dict]):
        """Add role nodes to graph"""
        for role in roles:
            node_id = role["id"]
            self.graph.add_node(node_id)
            
            self.id_to_name[node_id] = role["name"]
            self.name_to_id[role["name"]] = node_id
            
            # Risk scoring based on permissions
            risk_map = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
            risk_score = role.get("risk_score", risk_map.get(role.get("risk_level", "LOW"), 1.0))
            
            self.node_metadata[node_id] = {
                "id": node_id,
                "name": role["name"],
                "type": role.get("type", "Role"),
                "namespace": role.get("namespace"),
                "permissions": role.get("permissions", []),
                "risk_level": role.get("risk_level"),
                "risk_score": risk_score,
                "is_cluster_scope": role.get("type") == "ClusterRole",
                "is_entry_point": role.get("is_source", False),
                "is_crown_jewel": role.get("is_sink", False),
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_secret_nodes(self, secrets: List[Dict]):
        """Add secret nodes to graph"""
        for secret in secrets:
            node_id = secret["id"]
            self.graph.add_node(node_id)
            
            self.id_to_name[node_id] = secret["name"]
            self.name_to_id[secret["name"]] = node_id
            
            # High risk for crown jewels
            risk_map = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
            risk_score = secret.get("risk_score", risk_map.get(secret.get("sensitivity", "LOW"), 1.0))
            
            self.node_metadata[node_id] = {
                "id": node_id,
                "name": secret["name"],
                "type": "Secret",
                "namespace": secret.get("namespace"),
                "sensitivity": secret.get("sensitivity"),
                "is_crown_jewel": secret.get("is_crown_jewel", False) or secret.get("is_sink", False),
                "contains": secret.get("contains"),
                "risk_score": risk_score,
                "is_entry_point": secret.get("is_source", False),
                "is_sink": secret.get("is_sink", False),
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_edges_from_bindings(self, bindings: List[Dict]):
        """Add edges based on role bindings"""
        for binding in bindings:
            source = binding.get("source")
            target = binding.get("target")
            
            if source and target and source in self.graph and target in self.graph:
                weight = binding.get("weight", 1.0)
                
                edge_data = {
                    "weight": weight,
                    "binding_type": binding.get("type"),
                    "relationship": binding.get("type"),
                    "cve": {"cve_id": binding.get("cve"), "cvss": binding.get("cvss")} if binding.get("cve") else None,
                }
                
                self.graph.add_edge(source, target, **edge_data)
                self.edge_metadata[(source, target)] = edge_data
    
    def _add_role_to_secret_edges(self, cluster_data: Dict):
        """Add edges from roles with secret permissions to secrets"""
        # This is handled by explicit edges in the new format
        pass
    
    def get_node_name(self, node_id: str) -> str:
        """Get node name from ID"""
        return self.id_to_name.get(node_id, node_id)
    
    def get_node_id(self, node_name: str) -> str:
        """Get node ID from name"""
        return self.name_to_id.get(node_name, node_name)
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the graph"""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(self.graph),
            "density": nx.density(self.graph),
            "nodes_by_type": self._count_nodes_by_type(),
            "crown_jewels": self._get_crown_jewels(),
            "entry_points": self._get_entry_points(),
        }
    
    def _count_nodes_by_type(self) -> Dict[str, int]:
        """Count nodes by type"""
        type_counts = {}
        for node_id, metadata in self.node_metadata.items():
            node_type = metadata.get("type", "Unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1
        return type_counts
    
    def _get_crown_jewels(self) -> List[Dict]:
        """Get list of crown jewel nodes (high-value targets)"""
        crown_jewels = []
        for node_id, metadata in self.node_metadata.items():
            if metadata.get("is_crown_jewel") or metadata.get("is_sink") or metadata.get("risk_score", 0) >= 9.0:
                crown_jewels.append({
                    "id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "risk_score": metadata.get("risk_score"),
                })
        return crown_jewels
    
    def _get_entry_points(self) -> List[Dict]:
        """Get list of potential entry points (internet-facing)"""
        entry_points = []
        for node_id, metadata in self.node_metadata.items():
            if metadata.get("is_entry_point") or metadata.get("is_source") or metadata.get("exposed_to_internet"):
                entry_points.append({
                    "id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "cve": metadata.get("cve"),
                })
        return entry_points
    
    def export_for_visualization(self) -> Dict[str, Any]:
        """Export graph data for frontend visualization"""
        nodes = []
        edges = []
        
        for node_id in self.graph.nodes():
            metadata = self.node_metadata.get(node_id, {})
            nodes.append({
                "id": node_id,
                "label": metadata.get("name", node_id),
                "type": metadata.get("type", "Unknown"),
                "risk_score": metadata.get("risk_score", 0),
                **metadata
            })
        
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "weight": data.get("weight", 1.0),
                "type": data.get("binding_type", "Unknown"),
                "relationship": data.get("relationship", "Unknown"),
            })
        
        return {"nodes": nodes, "edges": edges}
