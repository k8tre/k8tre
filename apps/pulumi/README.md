# Pulumi Kubernetes Operator for K8TRE

This directory contains the Kubernetes manifests for deploying the Pulumi Kubernetes Operator within the K8TRE environment. The Pulumi Kubernetes Operator enables infrastructure as code management using Pulumi directly from Kubernetes.

Learn more at [https://www.pulumi.com/docs/iac/guides/continuous-delivery/pulumi-kubernetes-operator/](https://www.pulumi.com/docs/iac/guides/continuous-delivery/pulumi-kubernetes-operator/)

## Structure

- `base/` - Base Kubernetes manifests deploying the operator from upstream YAML
- `envs/` - Environment-specific configurations (dev/stg/prd)

## Notes

The operator is installed directly from the upstream Pulumi GitHub repository using raw YAML manifests.
