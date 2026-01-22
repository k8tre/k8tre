# Cert-Manager for K8TRE

This directory contains the Kubernetes manifests for deploying cert-manager within the K8TRE environment. Cert-manager automates the management and issuance of TLS certificates from various issuing sources.

Learn more at [https://cert-manager.io/](https://cert-manager.io/)

## Structure

- `base/` - Contains the base Kubernetes manifests including ClusterIssuer configurations
- `azure/` - Azure-specific configurations
- `k3s/` - K3S-specific configurations
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Vendor Differences

The implementation differs between Azure and K3S deployments. K3S deployments include self-signed certificate issuers for development environments, while Azure deployments may integrate with Azure-native certificate services.
