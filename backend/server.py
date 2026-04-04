"""Main FastAPI server with comprehensive API endpoints"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import os
from dotenv import load_dotenv

# Import all backend modules
from core.k8s_mock import generate_mock_cluster
from core.graph_engine import KubernetesGraphEngine
from core.algorithms import SecurityAlgorithms
from core.cve_scoring import CVEScorer
from analysis.attack_detector import AttackPathDetector
from analysis.blast_radius import BlastRadiusAnalyzer
from analysis.critical_nodes import CriticalNodeAnalyzer
from analysis.risk_scorer import RiskScorer
from ai.gemini_client import GeminiSecurityAnalyst
from ai.auto_fix import AutoFixGenerator
from reports.pdf_generator import KillChainReportGenerator
from reports.kill_chain import KillChainAnalyzer
from storage.snapshot_manager import SnapshotManager

load_dotenv()

# Initialize FastAPI
app = FastAPI(
    title="ClusterNodes Security Analysis API",
    description="Kubernetes Security Analysis Tool with Graph-based Attack Path Detection",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
graph_engine = None
cluster_data = None
current_analysis = {}

# Initialize managers
snapshot_manager = SnapshotManager()
report_generator = KillChainReportGenerator()
auto_fix_generator = AutoFixGenerator()

# Initialize CVE scorer with environment config
use_live_api = os.getenv("USE_LIVE_CVE_API", "true").lower() == "true"
nist_api_key = os.getenv("NIST_NVD_API_KEY")
cve_scorer_instance = CVEScorer(use_live_api=use_live_api, api_key=nist_api_key)

# Pydantic models
class ChatRequest(BaseModel):
    question: str
    context: Optional[Dict[str, Any]] = {}

class FixRequest(BaseModel):
    issue_type: str
    node_data: Dict[str, Any]

class SnapshotCompareRequest(BaseModel):
    snapshot_id1: str
    snapshot_id2: str


@app.get("/")
def root():
    """API root endpoint"""
    return {
        "message": "ClusterNodes Security Analysis API",
        "version": "1.0.0",
        "status": "running",
        "features": {
            "cve_api": "NIST NVD" if cve_scorer_instance.use_live_api else "Mock Data",
            "ai_chat": "Google Gemini Flash 2.0",
        },
        "endpoints": {
            "analyze": "/api/analyze",
            "graph": "/api/graph",
            "attack_paths": "/api/attack-paths",
            "blast_radius": "/api/blast-radius/{node_id}",
            "simulate": "/api/simulate/{node_id}",
            "critical_nodes": "/api/critical-nodes",
            "cve_scan": "/api/cve-scan",
            "ai_chat": "/api/ai-chat",
            "report_pdf": "/api/report/pdf",
            "snapshots": "/api/snapshots",
        }
    }


@app.get("/api/analyze")
def analyze_cluster():
    """Run comprehensive security analysis on the cluster"""
    global graph_engine, cluster_data, current_analysis
    
    try:
        # Generate mock cluster data
        cluster_data = generate_mock_cluster()
        
        # Build graph
        graph_engine = KubernetesGraphEngine()
        graph_engine.build_graph_from_cluster_data(cluster_data)
        
        # Initialize analyzers
        attack_detector = AttackPathDetector(graph_engine)
        blast_analyzer = BlastRadiusAnalyzer(graph_engine)
        critical_analyzer = CriticalNodeAnalyzer(graph_engine)
        risk_scorer = RiskScorer(graph_engine)
        # Use the initialized CVE scorer instance
        cve_analysis = cve_scorer_instance.scan_cluster_vulnerabilities(cluster_data)
        
        # Run all analyses
        graph_stats = graph_engine.get_graph_statistics()
        attack_paths = attack_detector.detect_all_attack_paths()
        critical_nodes = critical_analyzer.identify_critical_nodes()
        circular_perms = critical_analyzer.analyze_circular_permissions()
        # cve_analysis already defined above
        
        # Calculate risk
        risk_assessment = risk_scorer.calculate_cluster_risk_score(
            cluster_data,
            attack_paths.get("top_10_critical", [])
        )
        
        # Store current analysis
        current_analysis = {
            "graph_statistics": graph_stats,
            "attack_paths": attack_paths,
            "critical_nodes": critical_nodes.get("critical_nodes", []),
            "circular_permissions": circular_perms,
            "cve_analysis": cve_analysis,
            "risk_assessment": risk_assessment,
            "cluster_name": cluster_data.get("cluster_name"),
            "timestamp": cluster_data.get("timestamp"),
        }
        
        return {
            "status": "success",
            "analysis": current_analysis,
            "summary": {
                "risk_level": risk_assessment.get("risk_level"),
                "total_attack_paths": attack_paths.get("total_paths"),
                "critical_paths": attack_paths.get("by_severity", {}).get("critical_count", 0),
                "vulnerable_pods": cve_analysis.get("vulnerable_pods_count"),
                "critical_nodes_count": len(critical_nodes.get("critical_nodes", [])),
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/graph")
def get_graph_data():
    """Get graph data for visualization"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet. Call /api/analyze first.")
    
    try:
        graph_data = graph_engine.export_for_visualization()
        stats = graph_engine.get_graph_statistics()
        
        return {
            "graph": graph_data,
            "statistics": stats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export graph: {str(e)}")


@app.get("/api/attack-paths")
def get_attack_paths(max_length: int = 6):
    """Get all detected attack paths"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        attack_detector = AttackPathDetector(graph_engine)
        paths = attack_detector.detect_all_attack_paths(max_length)
        return paths
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to detect attack paths: {str(e)}")


@app.get("/api/attack-path/{source}/{target}")
def get_specific_attack_path(source: str, target: str):
    """Find specific attack path between two nodes"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        attack_detector = AttackPathDetector(graph_engine)
        path = attack_detector.find_specific_attack_path(source, target)
        return path
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to find path: {str(e)}")


@app.get("/api/blast-radius/{node_id}")
def get_blast_radius(node_id: str, max_hops: Optional[int] = None):
    """Calculate blast radius from a specific node"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        blast_analyzer = BlastRadiusAnalyzer(graph_engine)
        result = blast_analyzer.analyze_node_blast_radius(node_id, max_hops)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to calculate blast radius: {str(e)}")


@app.get("/api/simulate/{node_id}")
def simulate_attack(node_id: str):
    """Simulate an attack from an entry point"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        attack_detector = AttackPathDetector(graph_engine)
        simulation = attack_detector.simulate_attack_from_entry_point(node_id)
        return simulation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack simulation failed: {str(e)}")


@app.get("/api/critical-nodes")
def get_critical_nodes():
    """Get critical nodes analysis"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        critical_analyzer = CriticalNodeAnalyzer(graph_engine)
        result = critical_analyzer.identify_critical_nodes()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Critical nodes analysis failed: {str(e)}")


@app.get("/api/circular-permissions")
def get_circular_permissions():
    """Detect circular permission chains"""
    if not graph_engine:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        critical_analyzer = CriticalNodeAnalyzer(graph_engine)
        result = critical_analyzer.analyze_circular_permissions()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Circular permissions analysis failed: {str(e)}")


@app.get("/api/cve-scan")
def get_cve_scan():
    """Get CVE vulnerability scan results"""
    if not cluster_data:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        result = cve_scorer_instance.scan_cluster_vulnerabilities(cluster_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE scan failed: {str(e)}")


@app.post("/api/fix")
def generate_fix(request: FixRequest):
    """Generate remediation YAML for a security issue"""
    try:
        yaml_fix = auto_fix_generator.generate_comprehensive_fix(
            request.issue_type,
            request.node_data
        )
        return {
            "status": "success",
            "yaml": yaml_fix,
            "issue_type": request.issue_type,
            "node": request.node_data.get("name"),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fix generation failed: {str(e)}")


@app.post("/api/ai-chat")
async def ai_chat(request: ChatRequest):
    """AI-powered security chat"""
    try:
        analyst = GeminiSecurityAnalyst()  # Use async version
        
        # Add current analysis context
        context = request.context or {}
        if current_analysis:
            context.update({
                "total_nodes": current_analysis.get("graph_statistics", {}).get("total_nodes", 0),
                "critical_paths": current_analysis.get("attack_paths", {}).get("by_severity", {}).get("critical_count", 0),
                "vulnerable_pods": current_analysis.get("cve_analysis", {}).get("vulnerable_pods_count", 0),
            })
        
        # Await the async call
        response = await analyst.chat_query(request.question, context)
        return {"answer": response, "status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI chat failed: {str(e)}")


@app.get("/api/report/pdf")
def generate_pdf_report(background_tasks: BackgroundTasks):
    """Generate comprehensive PDF report"""
    if not current_analysis:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        # Prepare report data
        kill_chain_analyzer = KillChainAnalyzer()
        report_data = kill_chain_analyzer.prepare_report_data(
            current_analysis.get("graph_statistics", {}),
            current_analysis.get("attack_paths", {}),
            current_analysis.get("cve_analysis", {}),
            current_analysis.get("critical_nodes", []),
            current_analysis.get("risk_assessment", {}),
        )
        
        # Generate PDF
        filepath = report_generator.generate_report(report_data)
        
        return FileResponse(
            filepath,
            media_type="application/pdf",
            filename=os.path.basename(filepath)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@app.post("/api/snapshot")
def create_snapshot():
    """Create a new cluster snapshot"""
    if not cluster_data or not current_analysis:
        raise HTTPException(status_code=400, detail="No analysis has been run yet.")
    
    try:
        snapshot_id = snapshot_manager.create_snapshot(cluster_data, current_analysis)
        return {
            "status": "success",
            "snapshot_id": snapshot_id,
            "message": "Snapshot created successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Snapshot creation failed: {str(e)}")


@app.get("/api/snapshots")
def list_snapshots():
    """List all available snapshots"""
    try:
        snapshots = snapshot_manager.list_snapshots()
        return {
            "total": len(snapshots),
            "snapshots": snapshots
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list snapshots: {str(e)}")


@app.get("/api/snapshot/{snapshot_id}")
def get_snapshot(snapshot_id: str):
    """Get a specific snapshot"""
    try:
        snapshot = snapshot_manager.get_snapshot(snapshot_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return snapshot
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve snapshot: {str(e)}")


@app.post("/api/diff")
def compare_snapshots(request: SnapshotCompareRequest):
    """Compare two snapshots"""
    try:
        comparison = snapshot_manager.compare_snapshots(
            request.snapshot_id1,
            request.snapshot_id2
        )
        
        if "error" in comparison:
            raise HTTPException(status_code=404, detail=comparison["error"])
        
        return comparison
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Snapshot comparison failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8001))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
