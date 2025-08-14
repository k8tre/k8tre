# Application Sets for K8TRE

This directory contains ArgoCD ApplicationSet definitions that automatically create and manage multiple ArgoCD Applications across different environments.

## Structure

- `agnostics/` - ApplicationSets for platform agnostic infrastructure components
- `identity/` - Identity management ApplicationSets
- `workspaces/` - ApplicationSets for user-facing workspace applications

ApplicationSets enable K8TRE to maintain consistent configurations across development, staging, and production environments while allowing for environment-specific customizations.

## Agnostic ApplicationSets (`agnostics/`)

Platform-agnostic infrastructure components that work across different Kubernetes platforms:

- **`cert-manager.yaml`** - Certificate management and automatic TLS certificate provisioning
- **`cnpg.yaml`** - Cloud Native PostgreSQL operator for database management
- **`external-dns.yaml`** - Automatic DNS record management for Kubernetes services
- **`external-secrets.yaml`** - External Secrets Operator for secret management from external systems
- **`metallb.yaml`** - MetalLB load balancer for bare metal Kubernetes clusters
- **`nginx.yaml`** - NGINX ingress controller for HTTP/HTTPS traffic routing
- **`secret-store.yaml`** - Secret store configurations for external secret providers
- **`storage-class.yaml`** - Storage class definitions for persistent volume provisioning

## Identity ApplicationSets (`identity/`)

Identity and access management components:

- **`keycloak.yaml`** - Keycloak identity provider for authentication and authorization

## Workspace ApplicationSets (`workspaces/`)

User-facing workspace applications for development and collaboration:

- **`awms.yaml`** - Automated Workflow Management System for workflow orchestration
- **`jupyterhub.yaml`** - JupyterHub for collaborative Jupyter notebook environments

