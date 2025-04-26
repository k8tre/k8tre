# Postgres for K8TRE

This directory contains the Kubernetes manifests for deploying PostgreSQL database instances in the K8TRE environment.

## Structure

- `base/` - Contains the base Kubernetes manifests for PostgreSQL deployment
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

PostgreSQL instances are deployed using the Cloud Native PostgreSQL operator (CNPG) configured in the `agnostics/cnpg` directory.