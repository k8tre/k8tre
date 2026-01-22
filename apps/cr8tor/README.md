# CR8TOR for K8TRE

This directory contains the Kubernetes manifests for deploying CR8TOR within the K8TRE environment. CR8TOR is a workspace creator and management tool that integrates with Keycloak for authentication and authorization.

## Structure

- `base/` - Base Kubernetes manifests including external secrets and network policies
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Dependencies

- Keycloak for authentication and identity management
- External Secrets Operator for secret synchronization
- Cert-manager for TLS certificate management
