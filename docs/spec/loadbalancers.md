---
topic: Load Balancers
date: 2025-05-30
discussion: link
k8tre-statements:
  spec: There must be an off-cluster ingress load balancer - but it does not have to be ingress controller-managed. Services must be used to expose applications/components running in your cluster behind a single outward-facing endpoint.  
---

### Load Balancers

*Questions*: 

1. Where should load balancers be used in the K8TRE Reference Implementation?
2. Should a K8TRE be permitted to disaggregate load balancing from the ingress controller, so ought the K8TRE Specification leave the choice of which off-cluster load balancer up to implementers?
3. Where should they be mandatory/optional/recommended in the Specification?

    1. ? 
    2. ? Yes - as long as there is one..?
    3. We should describe where load balancers are required in K8TRE. 

*K8TRE Reference Implementation Statement*: AWS = , Azure = , K3S = ?