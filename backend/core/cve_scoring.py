"""CVE scoring and vulnerability assessment with NIST NVD API integration"""
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import time
import os
from functools import lru_cache

class CVEScorer:
    """CVE scoring system with real NIST NVD API integration and fallback mock data"""
    
    def __init__(self, use_live_api: bool = True, api_key: Optional[str] = None):
        """
        Initialize CVE scorer with optional live API
        
        Args:
            use_live_api: Whether to use real NIST NVD API (default: True)
            api_key: NIST NVD API key (optional, increases rate limit)
        """
        self.use_live_api = use_live_api
        self.api_key = api_key or os.getenv("NIST_NVD_API_KEY")
        self.api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting: 5 requests per 30 seconds without key, 50 with key
        self.rate_limit = 50 if self.api_key else 5
        self.rate_window = 30  # seconds
        self.last_requests = []
        
        # Cache for API responses (1 hour TTL)
        self.cache_ttl = 3600
        self.cache = {}
        
        # Fallback mock CVE database for offline/demo mode
        self.mock_cve_database = {
            "nginx:1.19": {
                "cve_id": "CVE-2021-23017",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
                "severity": "HIGH",
                "description": "nginx resolver off-by-one buffer overflow",
                "published": "2021-06-01",
                "exploitability": "HIGH",
                "source": "MOCK",
            },
            "redis:5.0": {
                "cve_id": "CVE-2021-32675",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "severity": "HIGH",
                "description": "Redis Lua script integer overflow",
                "published": "2021-10-04",
                "exploitability": "MEDIUM",
                "source": "MOCK",
            },
            "postgres:12": {
                "cve_id": "CVE-2021-32027",
                "cvss_score": 6.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "severity": "MEDIUM",
                "description": "PostgreSQL buffer overflow",
                "published": "2021-05-13",
                "exploitability": "MEDIUM",
                "source": "MOCK",
            },
            "ubuntu:18.04": {
                "cve_id": "CVE-2021-3711",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "CRITICAL",
                "description": "OpenSSL SM2 decryption buffer overflow",
                "published": "2021-08-24",
                "exploitability": "HIGH",
                "source": "MOCK",
            },
            "alpine:3.12": {
                "cve_id": "CVE-2021-36159",
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "severity": "MEDIUM",
                "description": "libfetch out-of-bounds read",
                "published": "2021-07-07",
                "exploitability": "LOW",
                "source": "MOCK",
            },
        }
    
    def _check_rate_limit(self):
        """Check if we're within rate limits"""
        now = time.time()
        # Remove requests older than rate window
        self.last_requests = [req for req in self.last_requests if now - req < self.rate_window]
        
        if len(self.last_requests) >= self.rate_limit:
            # Calculate wait time
            oldest_request = min(self.last_requests)
            wait_time = self.rate_window - (now - oldest_request) + 1
            print(f"Rate limit reached. Waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            self.last_requests = []
        
        self.last_requests.append(now)
    
    @lru_cache(maxsize=1000)
    def _parse_image_name(self, image: str) -> tuple:
        """Parse image name into components"""
        # Handle formats: nginx:1.19, nginx:latest, registry.io/nginx:1.19
        if '/' in image:
            # Remove registry
            image = image.split('/')[-1]
        
        if ':' in image:
            name, tag = image.split(':', 1)
        else:
            name, tag = image, 'latest'
        
        return name, tag
    
    def _fetch_cve_from_nist(self, image_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NIST NVD API"""
        try:
            self._check_rate_limit()
            
            # Build search query - search for product name
            params = {
                "keywordSearch": f"{image_name} {version}",
                "resultsPerPage": 5,
            }
            
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            response = requests.get(
                self.api_base_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    # Get the most severe CVE
                    cve_items = []
                    for vuln in vulnerabilities:
                        cve_data = vuln.get("cve", {})
                        cve_id = cve_data.get("id", "")
                        
                        # Extract CVSS score
                        metrics = cve_data.get("metrics", {})
                        cvss_score = 0.0
                        cvss_vector = ""
                        severity = "UNKNOWN"
                        
                        # Try CVSS v3.1 first, then v3.0, then v2.0
                        for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            if cvss_version in metrics and metrics[cvss_version]:
                                cvss_data = metrics[cvss_version][0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore", 0.0)
                                cvss_vector = cvss_data.get("vectorString", "")
                                severity = metrics[cvss_version][0].get("baseSeverity", "UNKNOWN")
                                break
                        
                        # Extract description
                        descriptions = cve_data.get("descriptions", [])
                        description = ""
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
                        
                        # Published date
                        published = cve_data.get("published", "")
                        
                        cve_items.append({
                            "cve_id": cve_id,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "severity": severity,
                            "description": description[:200] if description else "No description available",
                            "published": published,
                            "exploitability": self._estimate_exploitability(cvss_score),
                            "source": "NIST_NVD",
                        })
                    
                    # Return highest severity CVE
                    if cve_items:
                        cve_items.sort(key=lambda x: x["cvss_score"], reverse=True)
                        return cve_items[0]
            
            elif response.status_code == 403:
                print("NIST NVD API: Access forbidden. Check API key or rate limits.")
            elif response.status_code == 404:
                print(f"No CVE data found for {image_name}:{version}")
            else:
                print(f"NIST NVD API error: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print("NIST NVD API timeout. Using fallback data.")
        except requests.exceptions.RequestException as e:
            print(f"NIST NVD API error: {e}. Using fallback data.")
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
        
        return None
    
    def _estimate_exploitability(self, cvss_score: float) -> str:
        """Estimate exploitability based on CVSS score"""
        if cvss_score >= 9.0:
            return "HIGH"
        elif cvss_score >= 7.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_cve_for_image(self, image: str) -> Optional[Dict[str, Any]]:
        """Get CVE information for a container image"""
        # Check cache first
        cache_key = f"cve_{image}"
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                return cached_data
        
        cve_data = None
        
        # Try live API if enabled
        if self.use_live_api:
            image_name, version = self._parse_image_name(image)
            cve_data = self._fetch_cve_from_nist(image_name, version)
        
        # Fallback to mock data if API fails or disabled
        if not cve_data:
            cve_data = self.mock_cve_database.get(image)
        
        # Cache the result
        if cve_data:
            self.cache[cache_key] = (cve_data, time.time())
        
        return cve_data
    
    def calculate_cvss_score(self, cve_data: Dict[str, Any]) -> float:
        """Calculate CVSS score (already provided in mock data)"""
        return cve_data.get("cvss_score", 0.0)
    
    def assess_pod_vulnerability(self, pod_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerability of a pod based on its image"""
        image = pod_data.get("image", "")
        cve_info = self.get_cve_for_image(image)
        
        if not cve_info:
            return {
                "vulnerable": False,
                "risk_level": "LOW",
                "message": "No known CVEs for this image",
            }
        
        cvss_score = cve_info.get("cvss_score", 0)
        
        assessment = {
            "vulnerable": True,
            "cve_id": cve_info.get("cve_id"),
            "cvss_score": cvss_score,
            "severity": cve_info.get("severity"),
            "description": cve_info.get("description"),
            "exploitability": cve_info.get("exploitability"),
            "risk_level": self._calculate_risk_level(cvss_score, pod_data),
            "recommendations": self._generate_recommendations(cve_info, pod_data),
        }
        
        return assessment
    
    def _calculate_risk_level(self, cvss_score: float, pod_data: Dict[str, Any]) -> str:
        """Calculate overall risk level considering context"""
        base_risk = cvss_score
        
        # Amplify risk if pod is internet-facing
        if pod_data.get("exposed_to_internet"):
            base_risk += 2.0
        
        # Amplify risk if pod is privileged
        if pod_data.get("is_privileged"):
            base_risk += 1.5
        
        if base_risk >= 9.0:
            return "CRITICAL"
        elif base_risk >= 7.0:
            return "HIGH"
        elif base_risk >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, cve_info: Dict[str, Any], pod_data: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        image = pod_data.get("image", "")
        recommendations.append(f"Update image {image} to a patched version")
        
        if pod_data.get("exposed_to_internet"):
            recommendations.append("Consider adding network policy to restrict internet access")
            recommendations.append("Implement Web Application Firewall (WAF)")
        
        if pod_data.get("is_privileged"):
            recommendations.append("Run pod in non-privileged mode if possible")
            recommendations.append("Apply Pod Security Policy to restrict privileges")
        
        if cve_info.get("exploitability") == "HIGH":
            recommendations.append("URGENT: Patch immediately - high exploitability")
            recommendations.append("Enable runtime security monitoring")
        
        return recommendations
    
    def scan_cluster_vulnerabilities(self, cluster_data: Dict[str, Any]) -> Dict[str, Any]:
        """Scan entire cluster for vulnerabilities"""
        pods = cluster_data.get("pods", [])
        vulnerable_pods = []
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_cvss = 0.0
        
        for pod in pods:
            assessment = self.assess_pod_vulnerability(pod)
            if assessment.get("vulnerable"):
                vulnerable_pods.append({
                    "pod_name": pod.get("name"),
                    "pod_id": pod.get("id"),
                    "namespace": pod.get("namespace"),
                    **assessment
                })
                
                severity = assessment.get("severity", "LOW")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                total_cvss += assessment.get("cvss_score", 0)
        
        return {
            "total_pods_scanned": len(pods),
            "vulnerable_pods_count": len(vulnerable_pods),
            "vulnerable_pods": vulnerable_pods,
            "severity_distribution": severity_counts,
            "average_cvss_score": total_cvss / len(vulnerable_pods) if vulnerable_pods else 0,
            "overall_risk": self._calculate_cluster_risk(severity_counts),
            "scan_timestamp": datetime.now().isoformat(),
        }
    
    def _calculate_cluster_risk(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall cluster risk"""
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 2:
            return "HIGH"
        elif severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) > 3:
            return "MEDIUM"
        else:
            return "LOW"
