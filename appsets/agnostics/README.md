# Agnostic ApplicationSets

ArgoCD ApplicationSets for platform-agnostic infrastructure components in K8TRE.

## Components

- **`cilium.yaml`** - Cilium CNI for networking and network policies
- **`cnpg.yaml`** - Cloud Native PostgreSQL operator
- **`external-secrets.yaml`** - External Secrets Operator for secret management
- **`secret-store.yaml`** - Secret store configurations

These ApplicationSets deploy foundational components from the `/agnostics` directory across all K8TRE environments.