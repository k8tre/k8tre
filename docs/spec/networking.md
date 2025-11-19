---
topic: Networking
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/4
k8tre_statements:
  spec: All external access to applications/services must be via the ingress/gateway. The TREs must use a network plugin/CNI that fully supports Network Policy enforcement. 
  satre:
    - ref: 2.2.9
      rationale: SATRE requires TREs to control and manage all of their network infrastructure in order to protect information in systems and applications. This can be achieved in a managed or self-managed K8S cluster by using a CNI that supports Network Policies, and using Network Policies to control traffic flows within the cluster to ensure only authorized traffic is allowed.
      
      
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

FRIDGE makes extensive use of Cilium and standard Kubernetes network policies to ensure only the required network paths are open between componenents in the cluster. This also applies to ingress and egress traffic. Project isolation is not required in FRIDGE as a FRIDGE instance is currently dedicated to a project.

## FAQ

- **What capabilities must a CNI must provide the cluster to be K8TRE compliant?**

   A CNI must provide full support for standard [K8S Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/). Note the default K8s CNI in some public cloud providers _is not compliant_.

- **Should applications/services outside the cluster also have access to the CIDR/VPC/VNET**

   No. A K8TRE's CIDR/VPC/VNET is solely for in-cluster use only so all external access is via the ingress/gateway.
