# JupyterHub for K8TRE

This directory contains the Kubernetes manifests for deploying JupyterHub within the K8TRE environment. JupyterHub provides multi-user interactive computing environments through Jupyter notebooks.

## Structure

- `base/` - Contains the base Kubernetes manifests for JupyterHub deployment
  - `kustomization.yaml` - Base kustomization configuration
  - `network_policy.yaml` - Network policies for JupyterHub
  - `patch-rolebinding.yaml` - Role binding configurations
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prd/` - Production environment configuration with production-specific values
  - `stg/` - Staging environment configuration

JupyterHub is deployed as part of the workspace applications through the `appsets/workspaces/jupyterhub.yaml` ApplicationSet.