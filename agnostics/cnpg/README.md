# Cloud Native PostgreSQL (CNPG) for K8TRE

This directory contains the Kubernetes manifests for deploying the Cloud Native PostgreSQL operator within the K8TRE environment. CNPG enables declarative PostgreSQL database management in Kubernetes.

## Structure

- `base/` - Contains the base Kubernetes manifests for the CNPG operator
  - `kustomization.yaml` - Base kustomization configuration
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration with specific values
  - `prod/` - Production environment configuration with production-specific values
  - `stg/` - Staging environment configuration

CNPG is deployed as part of the platform agnostic components through the `appsets/agnostics/cnpg.yaml` ApplicationSet and is used by various applications in the K8TRE platform that require PostgreSQL databases.