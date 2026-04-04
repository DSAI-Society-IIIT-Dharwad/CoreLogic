"""Snapshot management for temporal analysis"""
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

class SnapshotManager:
    """Manages cluster state snapshots for temporal analysis"""
    
    def __init__(self, storage_dir: str = "/app/data/snapshots"):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
    
    def create_snapshot(self, cluster_data: Dict[str, Any], 
                        analysis_results: Dict[str, Any]) -> str:
        """Create and save a new cluster snapshot"""
        snapshot_id = f"snapshot-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now().isoformat()
        
        snapshot = {
            "id": snapshot_id,
            "timestamp": timestamp,
            "cluster_data": cluster_data,
            "analysis_results": analysis_results,
            "metadata": {
                "created_at": timestamp,
                "total_nodes": cluster_data.get("metadata", {}).get("total_nodes", 0),
                "risk_level": analysis_results.get("risk_level", "UNKNOWN"),
            }
        }
        
        # Save to file
        filepath = os.path.join(self.storage_dir, f"{snapshot_id}.json")
        with open(filepath, 'w') as f:
            json.dump(snapshot, f, indent=2)
        
        return snapshot_id
    
    def get_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a snapshot by ID"""
        filepath = os.path.join(self.storage_dir, f"{snapshot_id}.json")
        
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all available snapshots"""
        snapshots = []
        
        for filename in os.listdir(self.storage_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        snapshot = json.load(f)
                        snapshots.append({
                            "id": snapshot.get("id"),
                            "timestamp": snapshot.get("timestamp"),
                            "metadata": snapshot.get("metadata", {}),
                        })
                except Exception as e:
                    print(f"Error loading snapshot {filename}: {e}")
        
        # Sort by timestamp (newest first)
        snapshots.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return snapshots
    
    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str) -> Dict[str, Any]:
        """Compare two snapshots to detect changes"""
        snap1 = self.get_snapshot(snapshot_id1)
        snap2 = self.get_snapshot(snapshot_id2)
        
        if not snap1 or not snap2:
            return {"error": "One or both snapshots not found"}
        
        # Compare key metrics
        analysis1 = snap1.get("analysis_results", {})
        analysis2 = snap2.get("analysis_results", {})
        
        comparison = {
            "snapshot1_id": snapshot_id1,
            "snapshot1_time": snap1.get("timestamp"),
            "snapshot2_id": snapshot_id2,
            "snapshot2_time": snap2.get("timestamp"),
            
            "changes": {
                "risk_level": {
                    "before": analysis1.get("risk_level"),
                    "after": analysis2.get("risk_level"),
                    "changed": analysis1.get("risk_level") != analysis2.get("risk_level"),
                },
                "attack_paths": {
                    "before": analysis1.get("total_attack_paths", 0),
                    "after": analysis2.get("total_attack_paths", 0),
                    "delta": analysis2.get("total_attack_paths", 0) - analysis1.get("total_attack_paths", 0),
                },
                "vulnerable_pods": {
                    "before": analysis1.get("vulnerable_pods", 0),
                    "after": analysis2.get("vulnerable_pods", 0),
                    "delta": analysis2.get("vulnerable_pods", 0) - analysis1.get("vulnerable_pods", 0),
                },
            },
            
            "summary": self._generate_comparison_summary(analysis1, analysis2),
        }
        
        return comparison
    
    def _generate_comparison_summary(self, analysis1: Dict, analysis2: Dict) -> str:
        """Generate human-readable comparison summary"""
        risk1 = analysis1.get("risk_level", "UNKNOWN")
        risk2 = analysis2.get("risk_level", "UNKNOWN")
        
        paths1 = analysis1.get("total_attack_paths", 0)
        paths2 = analysis2.get("total_attack_paths", 0)
        path_delta = paths2 - paths1
        
        if risk1 == risk2 and path_delta == 0:
            return "No significant changes detected in security posture"
        elif risk2 < risk1 or path_delta < 0:
            return f"Security posture improved: Risk {risk1} -> {risk2}, Attack paths reduced by {abs(path_delta)}"
        else:
            return f"Security posture degraded: Risk {risk1} -> {risk2}, New attack paths detected: +{path_delta}"
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot"""
        filepath = os.path.join(self.storage_dir, f"{snapshot_id}.json")
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False
