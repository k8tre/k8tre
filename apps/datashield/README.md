# DataSHIELD for K8TRE

This directory contains the Kubernetes manifests for deploying DataSHIELD within the K8TRE environment. DataSHIELD provides federated data analysis capabilities, enabling privacy-preserving collaborative data analysis without sharing individual-level data.

## Structure

- `base/` - Contains the base Kubernetes manifests for DataSHIELD deployment
  - `kustomization.yaml` - Base kustomization configuration
  - `certificate.yaml` - TLS certificate configuration
  - `postgres.yaml` - PostgreSQL database cluster configuration
  - `storage-class.yaml` - Storage class configuration
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prd/` - Production environment configuration
  - `stg/` - Staging environment configuration with staging-specific values

DataSHIELD is deployed using the DataSHIELD Helm chart with CNPG PostgreSQL backend and is managed through the `federation/datashield.yaml` ApplicationSet.
