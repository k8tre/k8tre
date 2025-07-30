---
topic: Database
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/9
k8tre-statements:
  spec: K8TRE Specification-conformant apps shall allow the use of the default DB. A K8TRE should integrate with an organisation's existing databases where appropriate.
---

{{ spec_content(page.meta) }}

**Questions**:

1. **What should K8TRE Specification say about *in-cluster* DBs and what should it say about *off-cluster* DBs?**

    Databases should be attached resources, explicitly referenced

2. **What is K8TRE Reference Implementation doing regarding DBs?**

    PostrgeSQL DB needed on-cluster as part of default deployment

3. **How prescriptive should K8TRE Specification be in dictating how DB's are deployed and managed on-cluster?**

    Be very light-touch, non-prescriptive beyond best practice & decoupled/microservice architecture.
