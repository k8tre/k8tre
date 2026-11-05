# Trust-Manager for K8TRE

Trust-manager creates a shared certificate authority (CA) bundle that can optionally be mounted into pods.
This includes a standard CA bundle, with the addition of an internal private CA.

Learn more at [https://cert-manager.io/docs/trust/trust-manager/](https://cert-manager.io/docs/trust/trust-manager/)

## Structure

- `base/` - Contains the base Kubernetes manifests including ClusterIssuer configurations
- `envs/` - Environment-specific configurations (dev/stg/prd)
