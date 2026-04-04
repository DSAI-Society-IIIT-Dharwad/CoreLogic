from core.k8s_mock import MockK8sCluster

def generate_safe_cluster():
    cluster = MockK8sCluster()

    # Override CVE → no CRITICAL
    cluster.cve_database = {
        "nginx:1.21": {"cve_id": "CVE-2022-1111", "cvss_score": 5.0, "severity": "MEDIUM"},
        "redis:6.0": {"cve_id": "CVE-2022-2222", "cvss_score": 4.0, "severity": "LOW"},
    }

    data = cluster.generate_cluster_data()
    data["cluster_name"] = "safe-cluster"

    return data