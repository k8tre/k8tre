# Keycloak Operator for K8TRE

This directory contains the Kubernetes manifests for deploying the Keycloak Operator within the K8TRE environment. The Keycloak Operator provides automated management of Keycloak identity and access management instances.

## Structure

- `base/` - Contains the base Kubernetes manifests for the Keycloak Operator
  - `kustomization.yaml` - Base kustomization configuration
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

The Keycloak Operator is deployed as part of the platform agnostic components through the `appsets/agnostics/keycloak-operator.yaml` ApplicationSet and enables the deployment of Keycloak instances in the `apps/keycloak` directory.