from core.k8s_mock import MockK8sCluster

def generate_medium_cluster():
    cluster = MockK8sCluster()

    cluster.cve_database = {
        "nginx:1.19": {"cve_id": "CVE-2021-23017", "cvss_score": 7.5, "severity": "HIGH"},
        "postgres:12": {"cve_id": "CVE-2021-32027", "cvss_score": 6.5, "severity": "MEDIUM"},
    }

    data = cluster.generate_cluster_data()
    data["cluster_name"] = "medium-cluster"

    return data