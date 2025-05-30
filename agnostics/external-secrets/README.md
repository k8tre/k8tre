# External Secrets Operator for K8TRE

This directory contains the Kubernetes manifests for deploying the External Secrets Operator within the K8TRE environment. The External Secrets Operator enables secure integration with external secret management systems.

## Structure

- `base/` - Contains the base Kubernetes manifests for the External Secrets Operator (Empty at the moment)
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

The External Secrets Operator is deployed as part of the platform agnostic components through the `appsets/agnostics/external-secrets.yaml` ApplicationSet and enables applications in the K8TRE platform to securely retrieve secrets from external sources.
