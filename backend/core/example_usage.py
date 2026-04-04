"""
example_usage.py
----------------
Shows how to switch between live Kubernetes API data and mock data.
Run from the project root after installing dependencies:

    pip install kubernetes networkx requests
"""

import os
from graph_engine import KubernetesGraphEngine
from algorithms   import SecurityAlgorithms
from cve_scoring  import CVEScorer


# ── 1. Choose your data source ───────────────────────────────────────────────

USE_LIVE_CLUSTER = os.getenv("USE_LIVE_CLUSTER", "false").lower() == "true"

if USE_LIVE_CLUSTER:
    # ── LIVE: reads from your real cluster ──────────────────────────────────
    # Auth is auto-detected (in-cluster → kubeconfig → env vars K8S_HOST/K8S_TOKEN)
    from k8s_client import generate_live_cluster

    cluster_data = generate_live_cluster(
        # Optionally scope to specific namespaces:
        # namespaces=["production", "staging"],

        # Optionally point to a kubeconfig file:
        # kubeconfig_path="/path/to/kubeconfig",

        # Optionally pick a context:
        # context="my-prod-context",
    )
    print(f"✅ Fetched live cluster: {cluster_data['cluster_name']}")

else:
    # ── MOCK: no cluster required (good for CI / local dev) ─────────────────
    from k8s_mock import generate_mock_cluster

    cluster_data = generate_mock_cluster()
    print("🧪 Using mock cluster data")


# ── 2. Build the permission graph ────────────────────────────────────────────

engine = KubernetesGraphEngine()
graph  = engine.build_graph_from_cluster_data(cluster_data)
stats  = engine.get_graph_statistics()

print(f"\n📊 Graph stats: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
print(f"   Is DAG: {stats['is_dag']}")
print(f"   Node types: {stats['nodes_by_type']}")
print(f"   Crown jewels: {[n['name'] for n in stats['crown_jewels']]}")
print(f"   Entry points: {[n['name'] for n in stats['entry_points']]}")


# ── 3. Run security algorithms ───────────────────────────────────────────────

algos = SecurityAlgorithms(graph, engine.node_metadata)

# Blast radius from first entry point
entry_points = stats["entry_points"]
if entry_points:
    ep_id  = entry_points[0]["id"]
    result = algos.blast_radius_bfs(ep_id, max_hops=4)
    print(f"\n💥 Blast radius from '{result['start_node_name']}': "
          f"{result['total_reachable']} nodes reachable, "
          f"severity={result['severity']}, "
          f"crown jewels hit={len(result['crown_jewels_reached'])}")

# All attack paths
paths = algos.find_all_attack_paths(max_length=6)
print(f"\n🔴 Total attack paths found: {len(paths)}")
for p in paths[:3]:
    print(f"   • {p['entry_point']} → {p['crown_jewel']}  "
          f"(len={p['length']}, risk={p['total_risk']:.1f}, severity={p['severity']})")

# Circular permission detection
cycles = algos.detect_circular_permissions_dfs()
print(f"\n🔄 Circular permission chains: {len(cycles)}")

# Critical node analysis
critical = algos.critical_node_analysis()
print(f"\n🎯 Top critical nodes (by attack paths broken):")
for node in critical[:3]:
    print(f"   • {node['name']} ({node['type']}) — breaks {node['paths_broken']} paths "
          f"({node['impact_percentage']:.1f}%)")


# ── 4. CVE scanning ──────────────────────────────────────────────────────────

# Use live NIST NVD API or fallback mock
cve_scorer   = CVEScorer(use_live_api=False)   # flip to True for real NIST lookups
scan_results = cve_scorer.scan_cluster_vulnerabilities(cluster_data)

print(f"\n🛡️  CVE scan: {scan_results['vulnerable_pods_count']} / "
      f"{scan_results['total_pods_scanned']} pods vulnerable")
print(f"   Severity distribution: {scan_results['severity_distribution']}")
print(f"   Overall cluster risk: {scan_results['overall_risk']}")