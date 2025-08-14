# K8TRE Architecture

K8TRE reference implementation will be deployable to [Azure Kubernetes Service](https://azure.microsoft.com/en-us/products/kubernetes-service), [Amazon Elastic Kubernetes Service](https://aws.amazon.com/eks/) and to [K3S](https://k3s.io/) on on-prem infrastructure (eg. on baremetal or VM-based environments). 

This is achieved through a three-layered architecture depicted in the architecture diagram below.

![High-Level K8TRE Architecture](../img/K8TRE-high-level.png)

## Infrastructure Layer

The infrastructure layer provides everything that is required to support a CNCF-certified Kubernetes cluster for production workloads as well as the cluster itself. Some of the components in this layer would include:

- Networking: VNETs, SNETs, NSGs, Firewalls, DNS, Load balancers
- Identity management for IaaS/PaaS (eg. Entra for Azure); This is distinct from identity management within K8TRE itself
- Storage provide: eg. Longhorn or NFS for on-prem deployments, Azure Disk, File Share or Blob for AKS, etc.
- Infrastructure monitoring tools (eg. Proxmox monitoring, Azure Log Analytics)
- Secrets management (Azure Key vault, AWS Secrets manager)
- One or more Kubernetes clusters (K3s, AKS, EKS) with Cilium as the CNI and ArgoCD for GitOps

??? warning "K8TRE needs Cilium and ArgoCD"

    K8TRE needs **Cilium** as the default CNI with Layer 7 capabilities turned on for the other layers to work.
    This requires clusters to be configured correctly. For instance, K3S must be started with the flannel-backend turned off. AKS provides managed Cilium for free but charges for L7 capabilities. It is possible to swap this with BYO Cilium CNI.

    **ArgoCD** must be installed on the management cluster and ArgoCD must be configured with access to dev/stg/prod clusters and the appropriate cluster labels set. See [here](argocd.md) for more details.

## Agnostics Layer

This layer provides the necessary abstractions and common components that will allow the application layer to operate regardless of where K8TRE is deployed.
These include storage classes, cert-manager, External Secrets Operator and more. See [agnostics documentation](agnostics.md) for more information. 

## Application Layer

Finally, there is the application layer where the actual microservices that provide user facing functions are deployed. These include identity management (KeyCloak), workspace provisioning (JupyterHub), federation tools and more.

## GitOps

### Infrastructure Layer

K8TRE embraces GitOps and expects TRE operators deploying K8TRE to follow best practices when setting up the infrastructure layer. 

!!! warning "Remove when Azure repo is made public"

An opinionated implementation using on Azure complete with landing zone, security policies, hub-spoke networking, multiple AKS clusters, storage accounts, etc. is provided as IaC using Terraform and Terragrunt. This implementation uses Azure Verified Modules wherever possible and follows best practice guidelines. It also comes with a set of GitHub actions for CI/CD workflows. 

However, host organisations are free to setup their own infrastructre as long as it meets the requirements for K8TRE (and follows security best practices).

### Agnostics and Application Layers

These layers use ArgoCD for managing a multi-cluster setup. See [here](argocd.md) for further details.

## Environment promotion

Environment promotion between dev/stg/prod environments is currently achieved by simply promoting directory changes through `dev` --> `stg` --> `prod` and letting ArgoCD to automatically deploy these to the correct clusters. 

!!! warning "To be documented/implemented"
    
    - Git branching strategy for ArgoCD
    - Production code resides in the `main` branch
    - Developers should be able to switch selected apps or clusters to a feature branch
    - Use ArgoCD projects to restrict developer access to only certain applications
    
