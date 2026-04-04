from core.k8s_mock import MockK8sCluster

def generate_small_cluster():
    cluster = MockK8sCluster(
        num_pods=5,
        num_service_accounts=3,
        num_roles=4,
        num_secrets=2
    )

    data = cluster.generate_cluster_data()
    data["cluster_name"] = "small-cluster"

    return data