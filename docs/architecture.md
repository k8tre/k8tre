# K8TRE Architecture

![High-Level K8TRE Architecture](img/K8TRE-high-level.png)

## How the K8TRE Reference Implementation meets the K8TRE Specification

### BYO Software

### Container Runtimes

The K8TRE Reference Implementation uses the default high- and low-level container runtimes in the EKS, AKS, K3S Kubernetes distributions. 

### Databases

### DNS

### GitOps

The K8TRE Reference Implementation uses ArgoCD installed on a management cluster to manage nearly all resources on the child cluster(s) it manages. Here "nearly all" means ArgoCD will not be responsible for creating/destroying workspaces. JupyterHub is responsible for creating/destroying workspaces.

### Load Balancers

### Networking

### Secrets

### Storage