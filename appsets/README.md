# Application Sets for K8TRE

This directory contains ArgoCD ApplicationSet definitions that automatically create and manage multiple ArgoCD Applications across different environments.

## Structure

- `agnostics/` - ApplicationSets for platform agnostic components (Cilium, CNPG, Keycloak Operator)
- `workspaces/` - ApplicationSets for workspace applications (JupyterHub and other user-facing tools)

ApplicationSets enable K8TRE to maintain consistent configurations across development, staging, and production environments while allowing for environment-specific customizations.