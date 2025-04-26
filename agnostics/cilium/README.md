# Cilium for K8TRE

This directory contains the Kubernetes manifests for deploying Cilium within the K8TRE environment. Cilium provides networking, security, and observability for Kubernetes clusters.

## Structure

- `base/` - Contains the base Kubernetes manifests for Cilium
  - `kustomization.yaml` - Base kustomization configuration
  - `values.yaml` - Default Cilium configuration values
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

Cilium is deployed as part of the platform agnostic components through the `appsets/agnostics/cilium.yaml` ApplicationSet.
