## Cilium Network Policy Implementation in K8TRE

K8TRE uses Cilium as the default Container Network Interface (CNI) to provide advanced network security through network policies. Cilium is installed before ArgoCD during cluster setup and includes Hubble for network observability.

### Overview

Cilium network policies in K8TRE control network access between applications and external resources. This enables fine-grained control over researcher access to network resources - for example, allowing access to a TRE host organisation's package mirror while blocking access to public repositories like PyPI or CRAN.

### Why Cilium Over Default Kubernetes Network Policies

Cilium provides significant advantages over standard Kubernetes NetworkPolicy:

- **Layer 7 (Application) Filtering**: Can filter HTTP/HTTPS traffic based on URLs, headers, and methods, not just IP addresses and ports
- **DNS-based Rules**: Define policies using domain names instead of IP addresses, making policies more maintainable
- **Better Performance**: Uses eBPF for kernel-level filtering with sub-microsecond latency
- **Enhanced Observability**: Hubble provides detailed network flow visibility and policy violation monitoring

### Policy Types

#### Kubernetes NetworkPolicy
- Standard network policies for basic ingress/egress control
- Automatically enforced by Cilium's eBPF programs
- Layer 3/4 filtering based on pod selectors, namespaces, and ports

#### CiliumNetworkPolicy
- Advanced policies with Layer 7 filtering capabilities
- DNS-based rules for domain access control
- HTTP/HTTPS request filtering for fine-grained access control
- Essential for TRE environments where researchers need controlled access to specific external resources

### Implementation in K8TRE

Network policies in K8TRE are used to enforce security boundaries for all applications, including:

- **Research Workspaces**: Control researcher access to external package repositories and data sources
- **Administrative Services**: Secure communication between ArgoCD, Keycloak, and other management components
- **Cross-Namespace Communication**: Define allowed communication patterns between different application namespaces

### Policy Examples

#### Controlling Package Repository Access

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-internal-packages-only
spec:
  endpointSelector:
    matchLabels:
      app: research-workspace
  egress:
  - toFQDNs:
    - matchName: "internal-mirror.example.org"
  - toPorts:
    - ports:
      - port: "443"
        protocol: TCP
```

#### HTTP-based Access Control

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-specific-apis
spec:
  endpointSelector:
    matchLabels:
      app: data-analysis
  egress:
  - toFQDNs:
    - matchName: "api.internal.org"
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
      rules:
        http:
        - method: "GET"
```

### Observability with Hubble

Hubble is enabled in K8TRE's Cilium installation to provide network observability:

- **Network Flow Monitoring**: Real-time visibility into all network connections
- **Policy Violation Alerts**: Immediate notification when network policies block traffic
- **Performance Metrics**: Network latency and throughput monitoring
- **Security Insights**: Detect unusual network patterns and potential security threats

Use Hubble UI or CLI to monitor network policies and troubleshoot connectivity issues.