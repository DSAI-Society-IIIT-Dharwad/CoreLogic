from core.k8s_mock import MockK8sCluster

def generate_high_risk_cluster():
    cluster = MockK8sCluster()

    cluster.cve_database = {
        "ubuntu:18.04": {"cve_id": "CVE-2021-3711", "cvss_score": 9.8, "severity": "CRITICAL"},
        "nginx:1.19": {"cve_id": "CVE-2021-23017", "cvss_score": 8.1, "severity": "HIGH"},
    }

    data = cluster.generate_cluster_data()
    data["cluster_name"] = "high-risk-cluster"

    return data