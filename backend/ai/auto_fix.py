"""Auto-fix YAML generation for RBAC restrictions"""
from typing import Dict, Any, List

class AutoFixGenerator:
    """Generates YAML fixes for security issues"""
    
    def generate_network_policy_fix(self, pod_name: str, namespace: str = "default") -> str:
        """Generate NetworkPolicy to isolate a pod"""
        return f"""# Network Policy to restrict traffic to {pod_name}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {pod_name}-restricted
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      app: {pod_name}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
      - podSelector:
          matchLabels:
            access: {pod_name}
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
      - podSelector:
          matchLabels:
            app: backend
      ports:
        - protocol: TCP
          port: 5432
"""
    
    def generate_rbac_restriction_fix(self, sa_name: str, role_name: str, 
                                       namespace: str = "default") -> str:
        """Generate restricted RBAC role"""
        return f"""# Restricted RBAC Role for {sa_name}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {role_name}-restricted
  namespace: {namespace}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]  # Read-only access
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {sa_name}-{role_name}-binding
  namespace: {namespace}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {role_name}-restricted
subjects:
  - kind: ServiceAccount
    name: {sa_name}
    namespace: {namespace}
"""
    
    def generate_pod_security_policy_fix(self, pod_name: str) -> str:
        """Generate PodSecurityPolicy to restrict privileges"""
        return f"""# Pod Security Policy for {pod_name}
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: {pod_name}-restricted
spec:
  privileged: false  # Prevent privileged mode
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
"""
    
    def generate_secret_access_restriction(self, role_name: str, 
                                            allowed_secrets: List[str],
                                            namespace: str = "default") -> str:
        """Generate Role with restricted secret access"""
        secrets_list = "\n    ".join([f"- {s}" for s in allowed_secrets])
        
        return f"""# Restricted Secret Access for {role_name}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {role_name}-secret-restricted
  namespace: {namespace}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames:  # Only allow specific secrets
    {secrets_list}
    verbs: ["get"]  # Read-only
"""
    
    def generate_comprehensive_fix(self, issue_type: str, 
                                    node_data: Dict[str, Any]) -> str:
        """Generate comprehensive fix based on issue type"""
        
        if issue_type == "overprivileged_sa":
            return self.generate_rbac_restriction_fix(
                node_data.get("name", "service-account"),
                "limited-access",
                node_data.get("namespace", "default")
            )
        
        elif issue_type == "privileged_pod":
            return self.generate_pod_security_policy_fix(
                node_data.get("name", "pod")
            )
        
        elif issue_type == "network_exposure":
            return self.generate_network_policy_fix(
                node_data.get("name", "pod"),
                node_data.get("namespace", "default")
            )
        
        elif issue_type == "secret_access":
            return self.generate_secret_access_restriction(
                node_data.get("name", "role"),
                ["allowed-secret-1"],  # Would be dynamic in production
                node_data.get("namespace", "default")
            )
        
        else:
            return "# No specific fix template available for this issue type"
    
    def generate_attack_path_fix(self, path_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fixes to break an attack path"""
        path_details = path_data.get("path_details", [])
        
        if len(path_details) < 2:
            return {"error": "Path too short to generate fix"}
        
        # Target the second node in the path (first hop after entry point)
        target_node = path_details[1]
        
        fix_yaml = ""
        if target_node.get("type") == "ServiceAccount":
            fix_yaml = self.generate_rbac_restriction_fix(
                target_node.get("name"),
                "restricted",
                "default"
            )
        elif target_node.get("type") in ["Role", "ClusterRole"]:
            fix_yaml = self.generate_rbac_restriction_fix(
                "service-account",
                target_node.get("name"),
                "default"
            )
        
        return {
            "target_node": target_node.get("name"),
            "target_type": target_node.get("type"),
            "fix_yaml": fix_yaml,
            "explanation": f"Breaking the attack path by restricting permissions at {target_node.get('name')}",
        }
