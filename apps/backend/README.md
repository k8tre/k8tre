# K8TRE Backend for K8TRE

This directory contains the Kubernetes manifests for deploying the K8TRE Backend service. The backend provides API endpoints for managing K8TRE platform operations and integrates with Keycloak for authentication.

## Structure

- `base/` - Base Kubernetes manifests including deployment and service configurations
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Dependencies

- Keycloak for authentication and authorization
- Service account with appropriate RBAC permissions for Kubernetes operations
