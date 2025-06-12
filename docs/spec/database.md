---
topic: Database
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/9
k8tre-statements:
  spec: K8TRE Specification-conformant apps shall allow the use of the default DB. A K8TRE should integrate with an organisation's existing databases where appropriate.
  refimpl: The K8TRE Reference Implementation includes a default Postgres DB, for the general use of apps. CloudNativePG used with ArgoCD to configure and manage this  on-cluster DB.
---

### Database

*Questions*:
1. What should K8TRE Specification say about *in-cluster* DBs and what should it say about *off-cluster* DBs?
2. What is K8TRE Reference Implementation doing regarding DBs?
3. How prescriptive should K8TRE Specification be in dictating how DB's are deployed and managed on-cluster?

    1. Databases should be attached resources, explicitly referenced
    2. PostrgeSQL DB needed on-cluster as part of default deployment
    3. Be very light-touch, non-prescriptive beyond best practice & decoupled/microservice architecture.
