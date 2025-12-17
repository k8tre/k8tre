---
topic: Ingress
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/3
k8tre_statements:
  spec: Off-cluster load balancers may be provisioned by cloud load balancer controllers, or provisioned manually outside the cluster. The TRE must be able to handle inbound traffic and route it to services.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

The K8TRE Reference Implementation currently implements an NGINX Ingress Controller.

### TREu

TREu implements an NGINX Ingress Controller exposed to a AWS Network Load Balancer. A single public origin (Cloudflare in the ARC deployment) must be configured - no requests go to the NLB directly.

### FRIDGE

{{ satre_link(page.meta) }}

## FAQ

- **Are load balancers mandatory for a K8TRE?**

    No - the use of an external (i.e. off-cluster) load balancer is recommended, but not mandatory unless you're using services of type `LoadBalancer`.

- **Should one LB per app be discouraged on account of costs i.e. should K8TRE encourage use of ingress controller + services for load balancing?**

    If one load balancer can be used to support multiple applications (e.g. AWS ALB), then this is encouraged to reduce potentially high cloud costs.
