# Gitea for K8TRE

This directory contains the Kubernetes manifests for deploying Gitea within the K8TRE environment. Gitea is a lightweight, self-hosted Git service for source code management and collaboration.

Learn more at [https://gitea.io/](https://gitea.io/)

## Structure

- `base/` - Base Kubernetes manifests including PostgreSQL database and network policies
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Dependencies

- [CNPG Operator](https://cloudnative-pg.io/) for PostgreSQL database management
- [External Secrets Operator](https://external-secrets.io/) for secret synchronization
- Cilium Network Policies for network security
