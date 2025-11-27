---
topic: Networking
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/4
k8tre_statements:
  spec: All external access to applications/services must be via the ingress/gateway. The TRE must use a network plugin/CNI that fully supports Network Policy enforcement. Outbound connectivity should be blocked by default, or restricted by IP and port to pre-approved, trusted destinations.
  satre:
    - ref: 2.1.9
      rationale: SATRE requires TRE operators to mitigate and record any risks introduced by the use of software in the TRE that requires telemetry to function, such as licensed commercial software must contact an external licensing server. TRE operators may prohibit this entirely, or may allow it with appropriate risk mitigation and recording, but K8TRE components that facilitate the use of such software must support TRE operators in meeting this SATRE requirement.
    - ref: 2.2.9
      rationale: SATRE requires TRE operators to control and manage all of their network infrastructure in order to protect information in systems and applications. This can be achieved in a managed or self-managed K8S cluster by using a CNI that supports Network Policies, and using Network Policies to control traffic flows within the cluster to ensure only authorized traffic is allowed.
    - ref: 2.5.13
      rationale: SATRE requires TRE operators to encrypt data when in transit between the TRE and external networks or computers. Only allowing external access to applications/services via the ingress/gateway ensures this component can be fulfilled.
---

{{ spec_content(page.meta) }}

## Motivation

Robust network policy enforcement is required to isolate traffic, especially of sensitive data, but also of orchestration requests/responses that could be an attack vector - e.g. in runtime modification of access control lists.
    
## Implementation Compliance

### K8TRE Reference Implementation

K8TRE uses Cilium as the default Container Network Interface (CNI) to provide advanced network security through network policies. Cilium is installed before ArgoCD during cluster setup and includes Hubble for network observability.

### TREu

The (Kubernetes-based) System plane uses the Cilium CNI and network policies to control east-west traffic within the EKS cluster, allowing access to only the services/CIDRs that are required. Project network isolation is enacted at the compute platform level, e.g. using security groups in AWS.

### FRIDGE

FRIDGE makes extensive use of Cilium and standard Kubernetes network policies to ensure only the required network paths are open between components in the cluster. This also applies to ingress and egress traffic. Project isolation is not required in FRIDGE as a FRIDGE instance is currently dedicated to a project.

## FAQ

- **What capabilities must a CNI must provide the cluster to be K8TRE compliant?**

   A CNI must provide full support for standard [K8S Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/). Note the default K8s CNI in some public cloud providers _is not compliant_.

- **Should applications/services outside the cluster also have access to the CIDR/VPC/VNET**

   No. A K8TRE's CIDR/VPC/VNET is solely for in-cluster use only so all external access is via the ingress/gateway.
