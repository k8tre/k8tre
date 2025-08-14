# Applications

K8TRE implements a highly flexible and configurable pattern for deploying applications and microservices in a consistent manner across diverse environments. 
Microservices architecture allows K8TRE to use swappable components, add in new capabilities easily and enable or disable components as required.

The application layer of K8TRE should be deployable to any CNCF-certified Kubernetes distribution as long as the para-cluster infrastructure pre-requisites are met and the [_agnostics_ application plane](agnostics.md) can be deployed successfully. 

## KeyCloak

Keycloak is used for identity and access management in K8TRE. This Uses the Keycloak Bitnami Chart with PostgreSQL backend and External Secrets Operator for secret management.

**Dependencies**

- [CNPG Operator](https://cloudnative-pg.io/) for PostgreSQL
- [External Secrets Operator](https://external-secrets.io/) for secret synchronization

**Secret Management**

Secrets are automatically generated and managed using the CI script. To create required secrets:

```bash
# From the repository root
uv run ci/create-ci-secrets.py --context <your-kubectl-context>
```

This creates the following secrets in the `secret-store` namespace:
`keycloak-db-secret`

External Secrets Operator synchronizes these from the `secret-store` namespace into the `keycloak` namespace.

## JupyterHub

JupyterHub is used as the primary but not exclusive mechanism for provisioning researcher workspaces. _TBC_
