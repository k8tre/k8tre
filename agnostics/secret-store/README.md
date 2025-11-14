# Secret Store for K8TRE

Kubernetes secret store configurations for the External Secrets Operator.

## Structure

- `kubernetes/envs/` - Environment-specific secret store configurations
  - `dev/` - Development environment
  - `stg/` - Staging environment  
  - `prd/` - Production environment

Provides ClusterSecretStore resources that enable the External Secrets Operator to access secrets from Kubernetes clusters.
