# Agnostic ApplicationSets for K8TRE

This directory contains ArgoCD ApplicationSets for platform-agnostic infrastructure components that form the foundation of the K8TRE platform.

## Components

- `cilium.yaml` - ApplicationSet for deploying Cilium for networking and network policies
- `cnpg.yaml` - ApplicationSet for the Cloud Native PostgreSQL operator
- `keycloak-operator.yaml` - ApplicationSet for the Keycloak identity management operator

These ApplicationSets deploy the foundational components from the `/agnostics` directory across all K8TRE environments.