# NGINX Ingress Controller for K8TRE

This directory contains the Kubernetes manifests for deploying the NGINX Ingress Controller within the K8TRE environment. NGINX Ingress Controller manages external access to services in the Kubernetes cluster.

Learn more at [https://kubernetes.github.io/ingress-nginx/](https://kubernetes.github.io/ingress-nginx/)

## Structure

- `azure/` - Azure-specific configurations
- `k3s/` - K3S-specific configurations

## Vendor Differences

The NGINX Ingress Controller configuration varies between Azure and K3S deployments to accommodate platform-specific networking and load balancing requirements.
