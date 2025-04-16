# Cilium CNI Configuration

This directory contains the Helm chart for deploying Cilium CNI to all Kubernetes clusters.

## Overview

Cilium is a networking, observability, and security solution with an eBPF-based dataplane. This configuration:

- Deploys Cilium as the CNI provider
- Enables Hubble for network observability
- Configures Prometheus monitoring
- Uses Kubernetes services for IPAM

## Customization

To customize the Cilium deployment for specific environments:
- Create environment-specific value files (e.g., values-dev.yaml, values-prod.yaml)
- Adjust the ApplicationSet in `/appsets/agnostics/cilium.yaml` to use the appropriate values file

## Documentation

- [Cilium Documentation](https://docs.cilium.io/)
- [Hubble Documentation](https://docs.cilium.io/en/stable/gettingstarted/hubble/)
