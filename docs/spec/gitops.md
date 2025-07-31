---
topic: GitOps
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/7
k8tre-statements:
  spec:
---

{{ spec_content(page.meta) }}

**Questions**: 

1. What CI/CD tool is K8TRE going to use?

    Argo CD.

2. Should the tool deploy and manage applications to the same cluster it is installed on or deploy applications to other clusters? i.e. in-cluster vs cross-cluster architecture?

    Cross-cluster architecture supports two sub-models: 
        - deployment of K8TRE to dev/test/prod clusters from a single ArgoCD installation
        - deployment of one K8TRE per project or deployment of ephemeral K8TRE development environments for each developer.

3. What are the limits of what the CI/CD tool manages?

    In the JupyterHub control plane model, JupyterHub is responsible for creating/destroying workspaces, not ArgoCD. ArgoCD will complain that JupyterHub is out-of-sync because of the new resources but there are ways of addressing this.
