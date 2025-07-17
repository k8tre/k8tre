---
topic: Container Runtimes
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/12
k8tre-statements:
  spec: All default container runtimes on AKS, EKS, K3S carry the risk of container breakout. For most TRE operators, this wouldn't be considered a significant risk. TRE operators who can not tolerate the risk of container breakouts should consider using a more secure lower level runtimes such as Kata Containers or gVisor.
---

{{ spec_content(page.meta) }}

## Container Runtimes

**Questions**: 

1. **What container runtimes should a K8TRE implementation use, and why?**

    ?

2. **What statements about container runtimes must the K8TRE Specification make, pertaining to the capabilities that must be implemented by the underlying K8S platform?**

    
