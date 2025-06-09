---
topic: Networking
date: 2025-05-30
discussion: link
k8tre-statements:
  spec: A K8TRE's CIDR/VPC/VNET is solely for in-cluster use; all external access to applications/services is via the ingress object/load-balancer. A K8TRE's CNI must have full support for K8S Network Policies.  
---

### Networking

*Questions*: 

1. What capabilities must a CNI must provide the cluster to be K8TRE compliant?
2. What CNI will K8TRE Reference Implementation use?
3. Should a K8TRE's CIDR be solely for in-cluster use only, or should applications/services outside the cluster also have access to the CIDR/VPC/VNET

    1. Full support for K8S Network Policies? i.e. not AWS VPC CNI or Azure CNI..?
    2. Cilium vs Calico - Cilium preferred, used in ARC TRE and FRIDGE
    3. No. A K8TRE's CIDR/VPC/VNET is solely for in-cluster use only so all external access is via the ingress/load-balancer

*K8TRE Reference Implementation Statement*: Cilium is the chosen CNI ? 
All external access to applications/services is via the ingress object/load-balancer.