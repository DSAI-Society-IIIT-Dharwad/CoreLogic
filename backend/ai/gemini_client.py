"""Google Gemini AI client for security analysis"""
import os
from typing import Dict, Any, List
import google.genai as genai
from dotenv import load_dotenv

load_dotenv()

class GeminiSecurityAnalyst:
    """AI-powered security analyst using Google Gemini"""
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")
        
        genai.configure(api_key=self.api_key)
        
        self.model = genai.GenerativeModel(
            'gemini-2.0-flash',
            system_instruction="""You are a Kubernetes security expert specializing in RBAC, attack path analysis, 
and cloud-native security. Explain complex security issues in clear, actionable language. 
Provide specific YAML fixes when discussing remediation."""
        )
    
    async def analyze_attack_path(self, path_data: Dict[str, Any]) -> str:
        """Analyze an attack path and provide explanation"""
        
        path_details = path_data.get("path_details", [])
        path_description = " -> ".join([step.get("name", "") for step in path_details])
        
        prompt = f"""Analyze this Kubernetes attack path and explain the security risk:

Attack Path: {path_description}
Path Length: {len(path_details)} hops
Severity: {path_data.get('severity', 'Unknown')}
Total Risk Score: {path_data.get('total_risk_score', 0)}

Path Details:
{self._format_path_details(path_details)}

Provide:
1. Brief explanation of how this attack works
2. Why this is dangerous
3. Specific YAML configuration to block this path
"""
        
        return await self._query_gemini(prompt)
    
    async def explain_blast_radius(self, blast_radius_data: Dict[str, Any]) -> str:
        """Explain blast radius impact"""
        
        prompt = f"""Explain the blast radius from this compromised node:

Start Node: {blast_radius_data.get('start_node_name')}
Total Reachable Nodes: {blast_radius_data.get('total_reachable')}
Crown Jewels Reached: {len(blast_radius_data.get('crown_jewels_reached', []))}
Severity: {blast_radius_data.get('severity')}
Provide a clear explanation of:
1. What resources are at risk
2. The potential business impact
3. Priority remediation steps
"""
        
        return await self._query_gemini(prompt)
    
    async def generate_remediation_yaml(self, issue_description: str, 
                                         node_data: Dict[str, Any]) -> str:
        """Generate YAML configuration for remediation"""
        
        prompt = f"""Generate Kubernetes YAML to fix this security issue:

Issue: {issue_description}
Node Type: {node_data.get('type')}
Node Name: {node_data.get('name')}
Namespace: {node_data.get('namespace', 'default')}
Generate production-ready YAML that:
1. Follows least-privilege principle
2. Includes comments explaining the fix
3. Can be applied with kubectl apply -f

Provide ONLY the YAML, no additional explanation.
"""
        
        return await self._query_gemini(prompt)
    
    async def chat_query(self, user_question: str, context: Dict[str, Any]) -> str:
        """Answer security questions with context"""
        
        context_str = f"""Current Cluster Context:
- Total Nodes: {context.get('total_nodes', 'Unknown')}
- Critical Paths: {context.get('critical_paths', 0)}
- Vulnerable Pods: {context.get('vulnerable_pods', 0)}
- Crown Jewels: {context.get('crown_jewels', 0)}
"""
        
        prompt = f"{context_str}\n\nUser Question: {user_question}\n\nProvide a helpful, security-focused answer."
        
        return await self._query_gemini(prompt)
    
    async def generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """Generate executive summary of security analysis"""
        
        prompt = f"""Generate an executive summary of this Kubernetes security analysis:

Cluster Risk Level: {analysis_results.get('risk_level', 'Unknown')}
Total Attack Paths: {analysis_results.get('total_attack_paths', 0)}
Critical Paths: {analysis_results.get('critical_paths', 0)}
Vulnerable Pods: {analysis_results.get('vulnerable_pods', 0)}

Key Findings:
{self._format_key_findings(analysis_results)}

Provide:
1. Executive summary (3-4 sentences)
2. Top 3 risks
3. Immediate actions required
4. Estimated time to remediate
"""
        
        return await self._query_gemini(prompt)
    
    async def _query_gemini(self, prompt: str) -> str:
        """Query Gemini API"""
        try:
            response = await self.model.generate_content_async(prompt)
            return response.text
        except Exception as e:
            return f"Error querying AI: {str(e)}"
    
    def _format_path_details(self, path_details: List[Dict]) -> str:
        """Format path details for AI analysis"""
        formatted = []
        for step in path_details:
            formatted.append(
                f"Step {step.get('step')}: {step.get('name')} ({step.get('type')}) - "
                f"Risk Score: {step.get('risk_score')}"
            )
        return "\n".join(formatted)
    
    def _format_key_findings(self, results: Dict[str, Any]) -> str:
        """Format key findings for AI"""
        findings = []
        
        if results.get('critical_paths', 0) > 0:
            findings.append(f"- {results['critical_paths']} critical attack paths detected")
        
        if results.get('vulnerable_pods', 0) > 0:
            findings.append(f"- {results['vulnerable_pods']} pods with known CVEs")
        
        if results.get('circular_permissions', 0) > 0:
            findings.append(f"- {results['circular_permissions']} circular permission chains")
        
        return "\n".join(findings) if findings else "No major issues detected"