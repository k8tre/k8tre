# Keycloak for K8TRE

Keycloak deployment for identity and access management in K8TRE. Uses the Keycloak Operator with PostgreSQL backend and External Secrets Operator for secret management.

## Structure

- `base/` - Base Kubernetes manifests
- `envs/` - Environment-specific configurations (dev/stg/prod)

## Dependencies

- [Keycloak Operator](https://www.keycloak.org/guides#operator)
- [CNPG Operator](https://cloudnative-pg.io/) for PostgreSQL
- [External Secrets Operator](https://external-secrets.io/) for secret synchronization

## Secret Management

Secrets are automatically generated and managed using the CI script. To create required secrets:

```bash
# From the repository root
cd ci
uv run create-ci-secrets.py --context <your-kubectl-context>
```

This creates the following secrets in the `secret-store` namespace:
- `keycloak-db-secret` - Database credentials
- `keycloak-tls-secret` - TLS certificate

External Secrets Operator synchronizes these from the `secret-store` namespace into the `keycloak` namespace.