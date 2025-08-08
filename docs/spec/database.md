---
topic: Database
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/9
k8tre-statements:
  spec: The TRE must offer a Kubernetes-native mechanism for deploying relational databases on the cluster, and may also allow microservices to connect to off-cluster databases.
---

{{ spec_content(page.meta) }}

**Questions**:

1. **What should K8TRE Specification say about *in-cluster* DBs and what should it say about *off-cluster* DBs?**

    Databases should be attached resources, explicitly referenced. TRE administrators may use an externally provided database service, such as AWS RDS, but where applications can use an on-cluster database, they should consider using the CNPG operator to deploy an instance of Postgres DB, rather than using a different Postgres helm chart and introducing an additional a dependency.

2. **How prescriptive should the K8TRE Specification be in dictating how databases are deployed and managed on-cluster?**

    The specification should remain non-prescriptive, but it ought to encourage modern best practices for database management, such as using Kubernetes-native tools like database operators (e.g. the CloudNativePG operator), to align with a decoupled, microservices-oriented architecture.

