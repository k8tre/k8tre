# JupyterHub for K8TRE

This directory contains the Kubernetes manifests for deploying JupyterHub within the K8TRE environment. JupyterHub provides multi-user interactive computing environments through Jupyter notebooks.

## Structure

- `base/` - Contains the base Kubernetes manifests for JupyterHub deployment
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration with production-specific values
  - `stg/` - Staging environment configuration

JupyterHub is deployed as part of the workspace applications through the `appsets/workspaces/jupyterhub.yaml` ApplicationSet.

The following settings should be applied to the singleuser config across all environments.

```yaml
singleuser:
  cloudMetadata:
    # This requires elevated permissions which should be avoided. Use network policies instead.
    # See https://z2jh.jupyter.org/en/latest/administrator/security.html#audit-cloud-metadata-server-access
    blockWithIptables: false
  networkPolicy:
    enabled: false # These are managed by Cilium network policies
```
