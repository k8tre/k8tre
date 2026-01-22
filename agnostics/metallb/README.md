# MetalLB for K8TRE

This directory contains the Kubernetes manifests for deploying MetalLB within the K8TRE environment. MetalLB is a load-balancer implementation for bare metal Kubernetes clusters using standard routing protocols.

Learn more at [https://metallb.universe.tf/](https://metallb.universe.tf/)

## Structure

- `k3s/` - K3S-specific configurations including IP address pool definitions

## Vendor Differences

MetalLB is primarily used in K3S deployments for load balancing. Azure deployments typically use native Azure Load Balancer services instead.
