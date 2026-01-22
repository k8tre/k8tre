---
topic: Databases
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/9
k8tre_statements:
  spec: Databases should be treated as attached resources and may be deployed on the cluster, or apps may connect to off-cluster databases.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

The K8TRE Reference Implementation includes the CloudNativePG (CNPG) operator for Postgres and a default Postgres database. Applications can deploy their own Postgres databases in a consistent manner using the operator.

### TREu

TREu uses Postgres databases for use in its System cluster, specifically, for Apache Guacamole VDI and for API authorisation state, provisioned using the CNPG operator. TREu does not support databases containing project sensitive data on its System cluster: Projects are expected to deploy their own databases on Project VMs if required.

### FRIDGE

{{ satre_link(page.meta) }}

## FAQ

- **What should K8TRE Specification say about *in-cluster* DBs and what should it say about *off-cluster* DBs?**

   Databases should be attached resources, explicitly referenced. TRE administrators may use an externally provided database service, such as AWS RDS, but where applications can use an on-cluster database, they should consider using the CNPG operator to deploy an instance of Postgres DB, rather than using a different Postgres helm chart which introduces an additional dependency.

- **How prescriptive should the K8TRE Specification be in dictating how databases are deployed and managed on-cluster?**

   The specification should remain non-prescriptive, but it ought to encourage modern best practices for database management, such as using Kubernetes-native tools like database operators (e.g. the CloudNativePG operator), to align with a decoupled, microservices-oriented architecture.
