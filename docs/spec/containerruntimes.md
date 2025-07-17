---
topic: Container Runtimes
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/12
k8tre-statements:
  spec: All default container runtimes on AKS, EKS, K3S carry the risk of container breakout. For most TRE operators, this wouldn't be considered a significant risk. TRE operators who can not tolerate the risk of container breakouts should consider using a more secure lower level runtimes such as Kata Containers or gVisor.
---

{{ spec_content(page.meta) }}

**Questions**: 

1. **What container runtimes should a K8TRE implementation use, and why?**

    A K8TRE implementation may use the default CRI- and OCI-compliant container runtimes of their chosen Kubernetes distribution, or where a TRE operator's risk appetite is low enough that the container breakout risk using these runtimes is unacceptable, more secure OCI-compliant runtimes may be used e.g. Kata Containers, gVisor.

2. **What statements about container runtimes must the K8TRE Specification make, pertaining to the capabilities that must be implemented by the underlying K8S platform?**

    A K8TRE implementation's underlying Kubernetes platform needs to provide suitable project isolation for the TRE operator's risk appetite. The K8TRE Specification therefore needs to allow TRE operators to choose runtimes with increased security (allowing increased confidence in project isolation) should their preferences require it. However, the Specification must allow less risk averse operators to use the default CRI and OCI-compliant runtimes for EKS, AKS, and K3S.
