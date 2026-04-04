"""PDF report generation using FPDF2"""
from fpdf import FPDF
from typing import Dict, Any, List
from datetime import datetime
import os

class SecurityReportPDF(FPDF):
    """Custom PDF class for security reports"""
    
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(59, 130, 246)  # Blue theme
        self.cell(0, 10, 'ClusterNodes Security Analysis Report', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
    
    def chapter_title(self, title: str):
        self.set_font('Arial', 'B', 14)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(2)
    
    def section_title(self, title: str):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(59, 130, 246)
        self.cell(0, 8, title, 0, 1, 'L')
        self.ln(1)
    
    def body_text(self, text: str):
        self.set_font('Arial', '', 11)
        self.set_text_color(0, 0, 0)
        self.multi_cell(0, 6, text)
        self.ln(2)
    
    def add_metric_box(self, label: str, value: str, severity: str = "MEDIUM"):
        # Set color based on severity
        if severity == "CRITICAL":
            self.set_fill_color(239, 68, 68)  # Red
            text_color = (255, 255, 255)
        elif severity == "HIGH":
            self.set_fill_color(245, 158, 11)  # Orange
            text_color = (255, 255, 255)
        elif severity == "MEDIUM":
            self.set_fill_color(59, 130, 246)  # Blue
            text_color = (255, 255, 255)
        else:
            self.set_fill_color(34, 197, 94)  # Green
            text_color = (255, 255, 255)
        
        self.set_font('Arial', 'B', 10)
        self.set_text_color(*text_color)
        self.cell(45, 8, label, 1, 0, 'C', True)
        self.set_font('Arial', '', 10)
        self.cell(45, 8, str(value), 1, 1, 'C', True)

class KillChainReportGenerator:
    """Generates detailed Kill Chain PDF reports"""
    
    def __init__(self, output_dir: str = "/app/data/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive PDF report"""
        pdf = SecurityReportPDF()
        pdf.add_page()
        
        # Executive Summary
        self._add_executive_summary(pdf, analysis_results)
        
        # Cluster Overview
        self._add_cluster_overview(pdf, analysis_results)
        
        # Attack Paths
        self._add_attack_paths_section(pdf, analysis_results)
        
        # CVE Vulnerabilities
        self._add_cve_section(pdf, analysis_results)
        
        # Critical Nodes
        self._add_critical_nodes_section(pdf, analysis_results)
        
        # Recommendations
        self._add_recommendations_section(pdf, analysis_results)
        
        # Save PDF
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        pdf.output(filepath)
        
        return filepath
    
    def _add_executive_summary(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.chapter_title("Executive Summary")
        
        risk_level = data.get("risk_level", "UNKNOWN")
        pdf.body_text(f"Cluster Risk Level: {risk_level}")
        pdf.body_text(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        pdf.body_text(f"Cluster Name: {data.get('cluster_name', 'prod-cluster')}")
        pdf.ln(5)
        
        # Key Metrics
        pdf.section_title("Key Security Metrics")
        metrics = [
            ("Total Attack Paths", data.get("total_attack_paths", 0), "HIGH"),
            ("Critical Paths", data.get("critical_paths", 0), "CRITICAL"),
            ("Vulnerable Pods", data.get("vulnerable_pods", 0), "HIGH"),
            ("Crown Jewels at Risk", data.get("crown_jewels_at_risk", 0), "CRITICAL"),
        ]
        
        for label, value, severity in metrics:
            pdf.add_metric_box(label, value, severity)
        
        pdf.ln(10)
    
    def _add_cluster_overview(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.add_page()
        pdf.chapter_title("Cluster Overview")
        
        graph_stats = data.get("graph_statistics", {})
        
        pdf.body_text(f"Total Nodes in Graph: {graph_stats.get('total_nodes', 0)}")
        pdf.body_text(f"Total Edges (Permissions): {graph_stats.get('total_edges', 0)}")
        pdf.body_text(f"Graph Density: {graph_stats.get('density', 0):.4f}")
        
        pdf.ln(5)
        pdf.section_title("Nodes by Type")
        nodes_by_type = graph_stats.get("nodes_by_type", {})
        for node_type, count in nodes_by_type.items():
            pdf.body_text(f"  {node_type}: {count}")
        
        pdf.ln(5)
    
    def _add_attack_paths_section(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.add_page()
        pdf.chapter_title("Attack Paths Analysis")
        
        attack_paths = data.get("attack_paths", {})
        top_paths = attack_paths.get("top_10_critical", [])
        
        pdf.body_text(f"Total Attack Paths Detected: {attack_paths.get('total_paths', 0)}")
        pdf.ln(3)
        
        if top_paths:
            pdf.section_title("Top 10 Critical Attack Paths")
            
            for i, path in enumerate(top_paths[:10], 1):
                pdf.set_font('Arial', 'B', 11)
                pdf.cell(0, 7, f"Path #{i} - Severity: {path.get('severity', 'UNKNOWN')}", 0, 1)
                
                pdf.set_font('Arial', '', 10)
                pdf.body_text(f"  Entry: {path.get('entry_point', 'N/A')}")
                pdf.body_text(f"  Target: {path.get('crown_jewel', 'N/A')}")
                pdf.body_text(f"  Length: {path.get('length', 0)} hops")
                pdf.body_text(f"  Risk Score: {path.get('total_risk', 0):.2f}")
                pdf.ln(3)
        else:
            pdf.body_text("No critical attack paths detected.")
        
        pdf.ln(5)
    
    def _add_cve_section(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.add_page()
        pdf.chapter_title("CVE Vulnerabilities")
        
        cve_data = data.get("cve_analysis", {})
        
        pdf.body_text(f"Total Vulnerable Pods: {cve_data.get('vulnerable_pods_count', 0)}")
        pdf.body_text(f"Average CVSS Score: {cve_data.get('average_cvss_score', 0):.2f}")
        
        pdf.ln(5)
        pdf.section_title("Severity Distribution")
        severity_dist = cve_data.get("severity_distribution", {})
        for severity, count in severity_dist.items():
            pdf.body_text(f"  {severity}: {count}")
        
        pdf.ln(5)
        
        # List vulnerable pods
        vulnerable_pods = cve_data.get("vulnerable_pods", [])[:10]
        if vulnerable_pods:
            pdf.section_title("Top Vulnerable Pods")
            for pod in vulnerable_pods:
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, f"{pod.get('pod_name')} ({pod.get('namespace')})", 0, 1)
                pdf.set_font('Arial', '', 9)
                pdf.body_text(f"  CVE: {pod.get('cve_id', 'N/A')} - CVSS: {pod.get('cvss_score', 0)}")
                pdf.body_text(f"  Severity: {pod.get('severity', 'UNKNOWN')}")
                pdf.ln(2)
        
        pdf.ln(5)
    
    def _add_critical_nodes_section(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.add_page()
        pdf.chapter_title("Critical Nodes")
        
        critical_nodes = data.get("critical_nodes", [])
        
        if critical_nodes:
            pdf.body_text("Nodes critical to attack paths (removing them breaks multiple paths):")
            pdf.ln(3)
            
            for node in critical_nodes[:10]:
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, f"{node.get('name')} ({node.get('type')})", 0, 1)
                pdf.set_font('Arial', '', 9)
                pdf.body_text(f"  Paths Broken: {node.get('paths_broken', 0)}")
                pdf.body_text(f"  Impact: {node.get('impact_percentage', 0):.1f}%")
                pdf.body_text(f"  Criticality: {node.get('criticality', 'MEDIUM')}")
                pdf.ln(2)
        else:
            pdf.body_text("No critical nodes identified.")
        
        pdf.ln(5)
    
    def _add_recommendations_section(self, pdf: SecurityReportPDF, data: Dict[str, Any]):
        pdf.add_page()
        pdf.chapter_title("Remediation Recommendations")
        
        recommendations = data.get("recommendations", [])
        
        if recommendations:
            pdf.body_text("Priority actions to improve cluster security:")
            pdf.ln(3)
            
            for i, rec in enumerate(recommendations, 1):
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, f"{i}. Priority: {rec.get('priority', 'MEDIUM')}", 0, 1)
                pdf.set_font('Arial', '', 10)
                pdf.body_text(f"   {rec.get('action', '')}")
                pdf.ln(2)
        else:
            pdf.body_text("No specific recommendations at this time.")
        
        pdf.ln(10)
        pdf.section_title("Next Steps")
        pdf.body_text("1. Review and prioritize the identified security issues")
        pdf.body_text("2. Apply the recommended YAML fixes to your cluster")
        pdf.body_text("3. Re-run the analysis to verify improvements")
        pdf.body_text("4. Implement continuous monitoring for new threats")
