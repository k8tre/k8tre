# Introduction to Developing with K8TRE


K8TRE is a SATRE-compliant Trusted Research Environment (TRE) implementation on Kubernetes. This guide provides an overview for developers who want to contribute to or build applications for K8TRE.

## Developer Groups

There are two primary groups of developers working with K8TRE:

### 1. K8TRE Platform Developers

**Who:** Contributors developing the K8TRE platform itself - the core infrastructure, GitOps configurations, and platform components.

**What you'll work on:**
- ArgoCD GitOps configurations and application sets
- Kubernetes manifests and Kustomize overlays
- Infrastructure components (cert-manager, external-secrets, nginx, etc.)
- Platform testing and CI/CD pipelines

**Getting started:**
- Follow the [K3s Development Environment](k3s-dev.md) setup guide
- Review the [Contributing Guidelines](../../CONTRIBUTING.md)
- Explore the `agnostics/`, `appsets/`, and `apps/` directories
- Join discussions at [GitHub Discussions](https://github.com/orgs/k8tre/discussions)

### 2. Application Developers

**Who:** Researchers and developers creating applications, workflows, and analysis tools that run within the K8TRE environment.

**What you'll work on:**
- Custom applications and services for research workloads
- Helm charts for deploying research tools
- JupyterHub configurations and custom images
- Data analysis pipelines and workflows

**Getting started:**
- Review existing applications in the `apps/` directory (JupyterHub, Keycloak, AWMS)
- Understand the GitOps deployment model using ArgoCD
- Follow Kubernetes and Helm best practices for research environments
- Ensure applications comply with TRE security requirements

## Key Technologies

- **Kubernetes:** Container orchestration platform
- **ArgoCD:** GitOps continuous deployment
- **Helm:** Kubernetes package manager
- **Kustomize:** Kubernetes configuration management
- **JupyterHub:** Multi-user notebook environments
