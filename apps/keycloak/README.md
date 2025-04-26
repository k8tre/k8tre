# Keycloak for K8TRE

This directory contains the Kubernetes manifests for deploying Keycloak within the K8TRE environment. Keycloak provides identity and access management for securing the TRE infrastructure.

## Structure

- `base/` - Contains the base Kubernetes manifests for Keycloak deployment
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

Keycloak instances are deployed using the Keycloak Operator configured in the `agnostics/keycloak-operator` directory.