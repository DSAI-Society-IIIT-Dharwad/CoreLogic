"""
Real Kubernetes API client for fetching live cluster data.
Replaces MockK8sCluster for production use.

Requirements:
    pip install kubernetes

Authentication (pick one):
    1. In-cluster (running inside a pod):        auto-detected
    2. kubeconfig file (local dev):              auto-detected from ~/.kube/config
    3. Explicit kubeconfig path:                 set KUBECONFIG env var
    4. Service account token + host:             set K8S_HOST and K8S_TOKEN env vars
"""

import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVE database reused from mock (same shape, so graph_engine is unaffected)
# ---------------------------------------------------------------------------
_KNOWN_CVE_DB = {
    "nginx:1.19":   {"cve_id": "CVE-2021-23017", "cvss_score": 8.1, "severity": "HIGH"},
    "redis:5.0":    {"cve_id": "CVE-2021-32675", "cvss_score": 7.5, "severity": "HIGH"},
    "postgres:12":  {"cve_id": "CVE-2021-32027", "cvss_score": 6.5, "severity": "MEDIUM"},
    "ubuntu:18.04": {"cve_id": "CVE-2021-3711",  "cvss_score": 9.8, "severity": "CRITICAL"},
    "alpine:3.12":  {"cve_id": "CVE-2021-36159", "cvss_score": 5.3, "severity": "MEDIUM"},
}

# Namespaces to scan. None = all namespaces.
DEFAULT_NAMESPACES: Optional[List[str]] = None


class K8sClient:
    """
    Fetches live data from a Kubernetes cluster via the official Python SDK.

    The returned data structure is intentionally identical to
    MockK8sCluster.generate_cluster_data() so that KubernetesGraphEngine
    and the rest of the pipeline work without any changes.
    """

    def __init__(
        self,
        namespaces: Optional[List[str]] = None,
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
    ):
        """
        Args:
            namespaces:      List of namespaces to scan. None = all namespaces.
            kubeconfig_path: Explicit path to kubeconfig file (overrides KUBECONFIG env).
            context:         kubeconfig context to use (None = current context).
        """
        self.namespaces = namespaces or DEFAULT_NAMESPACES
        self._load_config(kubeconfig_path, context)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _load_config(self, kubeconfig_path: Optional[str], context: Optional[str]) -> None:
        """Load kubernetes config — in-cluster first, then kubeconfig."""
        try:
            from kubernetes import client, config as k8s_config
        except ImportError:
            raise ImportError(
                "The 'kubernetes' package is required.\n"
                "Install it with:  pip install kubernetes"
            )

        # Explicit token + host (CI/CD, secrets managers, etc.)
        k8s_host = os.getenv("K8S_HOST")
        k8s_token = os.getenv("K8S_TOKEN")
        k8s_ca = os.getenv("K8S_CA_CERT")          # optional path to CA bundle

        if k8s_host and k8s_token:
            configuration = client.Configuration()
            configuration.host = k8s_host
            configuration.api_key = {"authorization": f"Bearer {k8s_token}"}
            if k8s_ca:
                configuration.ssl_ca_cert = k8s_ca
            else:
                configuration.verify_ssl = False
            client.Configuration.set_default(configuration)
            logger.info("Kubernetes: using explicit token/host from environment.")
            return

        # In-cluster (running inside a pod)
        try:
            k8s_config.load_incluster_config()
            logger.info("Kubernetes: using in-cluster config.")
            return
        except k8s_config.ConfigException:
            pass

        # kubeconfig file
        kubeconfig_path = kubeconfig_path or os.getenv("KUBECONFIG")
        k8s_config.load_kube_config(config_file=kubeconfig_path, context=context)
        logger.info("Kubernetes: using kubeconfig file (context=%s).", context or "current")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_cluster_data(self) -> Dict[str, Any]:
        """
        Fetch live cluster data and return it in the same shape as
        MockK8sCluster.generate_cluster_data().
        """
        from kubernetes import client as k8s

        core_v1   = k8s.CoreV1Api()
        rbac_v1   = k8s.RbacAuthorizationV1Api()

        pods             = self._fetch_pods(core_v1)
        service_accounts = self._fetch_service_accounts(core_v1)
        roles            = self._fetch_roles(rbac_v1)
        secrets          = self._fetch_secrets(core_v1)
        role_bindings    = self._fetch_role_bindings(rbac_v1, pods, service_accounts, roles)

        cluster_name = self._detect_cluster_name()

        return {
            "timestamp":    datetime.now().isoformat(),
            "cluster_name": cluster_name,
            "pods":             pods,
            "service_accounts": service_accounts,
            "roles":            roles,
            "secrets":          secrets,
            "role_bindings":    role_bindings,
            "metadata": {
                "total_nodes": len(pods) + len(service_accounts) + len(roles) + len(secrets),
                "namespaces":  self.namespaces or ["<all>"],
            },
        }

    # ------------------------------------------------------------------
    # Pods
    # ------------------------------------------------------------------

    def _fetch_pods(self, core_v1) -> List[Dict[str, Any]]:
        raw = self._list_namespaced_or_all(
            core_v1.list_namespaced_pod,
            core_v1.list_pod_for_all_namespaces,
        )
        pods = []
        for pod in raw.items:
            # Use first container image for CVE lookup
            containers = pod.spec.containers or []
            image = containers[0].image if containers else "unknown"
            cve_info = _KNOWN_CVE_DB.get(image, {})

            # Detect privileged containers
            is_privileged = any(
                (c.security_context and c.security_context.privileged)
                for c in containers
            )

            # Detect internet-facing via service labels (heuristic)
            labels = pod.metadata.labels or {}
            exposed = labels.get("exposed-to-internet", "false").lower() == "true"

            pods.append({
                "id":                 f"pod-{pod.metadata.uid}",
                "name":               pod.metadata.name,
                "namespace":          pod.metadata.namespace,
                "image":              image,
                "type":               "Pod",
                "created":            _ts(pod.metadata.creation_timestamp),
                "is_privileged":      is_privileged,
                "exposed_to_internet": exposed,
                "cve":                cve_info,
                "labels":             labels,
                "status":             pod.status.phase if pod.status else "Unknown",
                "node_name":          pod.spec.node_name,
            })
        return pods

    # ------------------------------------------------------------------
    # Service Accounts
    # ------------------------------------------------------------------

    def _fetch_service_accounts(self, core_v1) -> List[Dict[str, Any]]:
        raw = self._list_namespaced_or_all(
            core_v1.list_namespaced_service_account,
            core_v1.list_service_account_for_all_namespaces,
        )
        results = []
        for sa in raw.items:
            # auto_mount_token: SA-level default (pod can override)
            auto_mount = sa.automount_service_account_token
            if auto_mount is None:
                auto_mount = True   # k8s default

            results.append({
                "id":               f"sa-{sa.metadata.uid}",
                "name":             sa.metadata.name,
                "namespace":        sa.metadata.namespace,
                "type":             "ServiceAccount",
                "auto_mount_token": auto_mount,
                "created":          _ts(sa.metadata.creation_timestamp),
            })
        return results

    # ------------------------------------------------------------------
    # Roles + ClusterRoles
    # ------------------------------------------------------------------

    def _fetch_roles(self, rbac_v1) -> List[Dict[str, Any]]:
        results = []

        # Namespace-scoped Roles
        raw_roles = self._list_namespaced_or_all(
            rbac_v1.list_namespaced_role,
            rbac_v1.list_role_for_all_namespaces,
        )
        for role in raw_roles.items:
            results.append(self._parse_role(role, cluster_scope=False))

        # Cluster-scoped ClusterRoles
        cluster_roles = rbac_v1.list_cluster_role()
        for role in cluster_roles.items:
            results.append(self._parse_role(role, cluster_scope=True))

        return results

    def _parse_role(self, role, cluster_scope: bool) -> Dict[str, Any]:
        permissions = []
        for rule in (role.rules or []):
            resources = rule.resources or ["*"]
            verbs     = rule.verbs     or ["*"]
            for res in resources:
                permissions.append(f"{res}:{','.join(verbs)}")

        risk_level = _assess_role_risk(permissions)

        return {
            "id":          f"role-{role.metadata.uid}",
            "name":        role.metadata.name,
            "namespace":   role.metadata.namespace,
            "type":        "ClusterRole" if cluster_scope else "Role",
            "permissions": permissions,
            "risk_level":  risk_level,
            "created":     _ts(role.metadata.creation_timestamp),
        }

    # ------------------------------------------------------------------
    # Secrets
    # ------------------------------------------------------------------

    def _fetch_secrets(self, core_v1) -> List[Dict[str, Any]]:
        raw = self._list_namespaced_or_all(
            core_v1.list_namespaced_secret,
            core_v1.list_secret_for_all_namespaces,
        )
        results = []
        for secret in raw.items:
            sensitivity, contains = _classify_secret(secret.metadata.name, secret.type or "")
            results.append({
                "id":           f"secret-{secret.metadata.uid}",
                "name":         secret.metadata.name,
                "namespace":    secret.metadata.namespace,
                "type":         "Secret",
                "secret_type":  secret.type,
                "sensitivity":  sensitivity,
                "contains":     contains,
                "is_crown_jewel": sensitivity == "CRITICAL",
                "created":      _ts(secret.metadata.creation_timestamp),
            })
        return results

    # ------------------------------------------------------------------
    # RoleBindings + ClusterRoleBindings → edges
    # ------------------------------------------------------------------

    def _fetch_role_bindings(
        self, rbac_v1,
        pods: List[Dict], service_accounts: List[Dict], roles: List[Dict]
    ) -> List[Dict[str, Any]]:
        """
        Convert RoleBindings/ClusterRoleBindings into the flat edge list
        expected by KubernetesGraphEngine._add_edges_from_bindings().

        We emit edges:
            ServiceAccount  ──► Role / ClusterRole
        and infer:
            Pod  ──► ServiceAccount  (via pod.spec.serviceAccountName)
        """
        from kubernetes import client as k8s

        core_v1 = k8s.CoreV1Api()
        bindings: List[Dict[str, Any]] = []

        # Build lookup maps
        sa_map    = {(s["namespace"], s["name"]): s["id"] for s in service_accounts}
        role_map  = {(r["namespace"], r["name"]): r["id"] for r in roles}
        role_map.update({(None, r["name"]): r["id"] for r in roles if r["type"] == "ClusterRole"})

        # --- SA → Role from RoleBindings ---
        raw_rb = self._list_namespaced_or_all(
            rbac_v1.list_namespaced_role_binding,
            rbac_v1.list_role_binding_for_all_namespaces,
        )
        for rb in raw_rb.items:
            role_ref_id = role_map.get(
                (rb.metadata.namespace, rb.role_ref.name)
            ) or role_map.get((None, rb.role_ref.name))

            for subject in (rb.subjects or []):
                if subject.kind != "ServiceAccount":
                    continue
                ns  = subject.namespace or rb.metadata.namespace
                sa_id = sa_map.get((ns, subject.name))
                if sa_id and role_ref_id:
                    bindings.append({
                        "id":          f"rb-{rb.metadata.uid}-{subject.name}",
                        "type":        "ServiceAccountToRole",
                        "source":      sa_id,
                        "source_name": subject.name,
                        "target":      role_ref_id,
                        "target_name": rb.role_ref.name,
                    })

        # --- SA → ClusterRole from ClusterRoleBindings ---
        cluster_rbs = rbac_v1.list_cluster_role_binding()
        for crb in cluster_rbs.items:
            role_ref_id = role_map.get((None, crb.role_ref.name))
            for subject in (crb.subjects or []):
                if subject.kind != "ServiceAccount":
                    continue
                sa_id = sa_map.get((subject.namespace, subject.name))
                if sa_id and role_ref_id:
                    bindings.append({
                        "id":          f"crb-{crb.metadata.uid}-{subject.name}",
                        "type":        "ServiceAccountToRole",
                        "source":      sa_id,
                        "source_name": subject.name,
                        "target":      role_ref_id,
                        "target_name": crb.role_ref.name,
                    })

        # --- Pod → SA (from live pod specs) ---
        raw_pods = self._list_namespaced_or_all(
            core_v1.list_namespaced_pod,
            core_v1.list_pod_for_all_namespaces,
        )
        pod_id_map = {(p["namespace"], p["name"]): p["id"] for p in pods}
        for pod in raw_pods.items:
            sa_name = pod.spec.service_account_name or "default"
            ns      = pod.metadata.namespace
            pod_id  = pod_id_map.get((ns, pod.metadata.name))
            sa_id   = sa_map.get((ns, sa_name))
            if pod_id and sa_id:
                bindings.append({
                    "id":          f"pod-sa-{pod.metadata.uid}",
                    "type":        "PodToServiceAccount",
                    "source":      pod_id,
                    "source_name": pod.metadata.name,
                    "target":      sa_id,
                    "target_name": sa_name,
                })

        return bindings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _list_namespaced_or_all(self, namespaced_fn, all_fn):
        """Call namespace-scoped or cluster-wide list depending on config."""
        if self.namespaces:
            # Merge results from each namespace
            class _Merged:
                items = []
            merged = _Merged()
            for ns in self.namespaces:
                try:
                    merged.items += namespaced_fn(namespace=ns).items
                except Exception as exc:
                    logger.warning("Could not list in namespace %s: %s", ns, exc)
            return merged
        return all_fn()

    def _detect_cluster_name(self) -> str:
        try:
            from kubernetes import config as k8s_config
            contexts, active = k8s_config.list_kube_config_contexts()
            return active.get("context", {}).get("cluster", "live-cluster")
        except Exception:
            return "live-cluster"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _ts(dt) -> str:
    """Convert a kubernetes datetime to ISO string."""
    if dt is None:
        return datetime.now().isoformat()
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def _assess_role_risk(permissions: List[str]) -> str:
    """Heuristic risk level based on permissions list."""
    perms_str = " ".join(permissions).lower()
    if "*" in perms_str or "rbac" in perms_str or "etcd" in perms_str:
        return "CRITICAL"
    if "secrets" in perms_str or "exec" in perms_str or "nodes" in perms_str:
        return "HIGH"
    if "configmaps" in perms_str or "deployments" in perms_str:
        return "MEDIUM"
    return "LOW"


def _classify_secret(name: str, secret_type: str) -> tuple:
    """Return (sensitivity, description) for a secret."""
    name_lower = name.lower()

    if any(k in name_lower for k in ("db-cred", "database", "aws", "gcp", "azure",
                                      "encryption", "master")):
        return "CRITICAL", "cloud/database credentials or encryption keys"

    if any(k in name_lower for k in ("api-key", "jwt", "oauth", "tls", "ssh",
                                      "token", "cert", "private")):
        return "HIGH", "authentication or cryptographic material"

    if secret_type == "kubernetes.io/dockerconfigjson":
        return "MEDIUM", "container registry credentials"

    if secret_type == "kubernetes.io/service-account-token":
        return "MEDIUM", "service account token"

    return "LOW", "general secret"


# ---------------------------------------------------------------------------
# Convenience factory — mirrors generate_mock_cluster() in k8s_mock.py
# ---------------------------------------------------------------------------

def generate_live_cluster(
    namespaces: Optional[List[str]] = None,
    kubeconfig_path: Optional[str] = None,
    context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Drop-in replacement for k8s_mock.generate_mock_cluster().

    Usage:
        from k8s_client import generate_live_cluster
        cluster_data = generate_live_cluster()
        # or, scope to specific namespaces:
        cluster_data = generate_live_cluster(namespaces=["production", "staging"])
    """
    client = K8sClient(
        namespaces=namespaces,
        kubeconfig_path=kubeconfig_path,
        context=context,
    )
    return client.generate_cluster_data()