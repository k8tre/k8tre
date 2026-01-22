# Apache Guacamole for K8TRE

This directory contains the Kubernetes manifests for deploying Apache Guacamole within the K8TRE environment. Guacamole is a clientless remote desktop gateway that supports standard protocols like VNC, RDP, and SSH.

Learn more at [https://guacamole.apache.org/](https://guacamole.apache.org/)

## Structure

- `base/` - Base Kubernetes manifests including auth proxy deployment and external secrets
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Dependencies

- External Secrets Operator for secret management
- Authentication proxy for integration with K8TRE authentication
