# Applications for K8TRE

This directory contains the Kubernetes manifests for deploying applications that run on the K8TRE platform.

## Structure
- `awms/` - Analytics Workspace Management Solution for Jupyterhub
- `jupyterhub/` - JupyterHub for interactive data science and analytics workspaces
- `keycloak/` - Keycloak for identity and access management

Each application follows a standardized structure with a `base/` directory for common configurations and an `envs/` directory with environment-specific customizations for development, staging, and production environments.