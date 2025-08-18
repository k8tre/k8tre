---
topic: Networking
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/4
k8tre_statements:
  spec: All external access to applications/services must be via the ingress/gateway. The TREs must use a network plugin/CNI that fully supports Network Policy enforcement. 
---

{{ spec_content(page.meta) }}
    
## Implementation Compliance

### K8TRE Reference Implementation

K8TRE uses Cilium as the default Container Network Interface (CNI) to provide advanced network security through network policies. Cilium is installed before ArgoCD during cluster setup and includes Hubble for network observability.

### UCL ARC TRE

the (Kubernetes-based) system plane uses the Cilium CNI and network policies to control east-west traffic within the EKS cluster, allowing access to only the services/CIDRs that are required.

### FRIDGE

## FAQ

- **What capabilities must a CNI must provide the cluster to be K8TRE compliant?**

   Full support for K8S Network Policies? i.e. not AWS VPC CNI or Azure CNI..?

- **Should applications/services outside the cluster also have access to the CIDR/VPC/VNET**

   No. A K8TRE's CIDR/VPC/VNET is solely for in-cluster use only so all external access is via the ingress/gateway.
