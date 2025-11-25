---
topic: GitOps
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/7
k8tre_statements:
  spec: The TRE should employ GitOps practices when provisioning both K8TRE resources as well as any other required infrastructure level resources within the TRE.
  satre:
    - ref: 1.2.2
      rationale: SATRE requires the use of versioning and a codified change procedure for all policies and standard operating procedures. By using GitOps practices to provision and manage K8TRE resources and infrastructure-level resources, K8TRE developers are able to assist TRE operators in meeting this SATRE requirement for the policies and standard operating procedures that govern the TRE's infrastructure and configuration.
    - ref: 2.2.1
      rationale: SATRE requires TRE operators to have a documented procedure for deploying infrastructure. Designing TREs or TRE components with GitOps practices in mind will ensure this component is fulfilled. 
    - ref: 2.2.3
      rationale: SATRE requires TRE operators to have a documented procedure for making changes to deployed infrastructure. Designing TREs or TRE components with GitOps practices in mind will ensure this component is fulfilled. 
    - ref: 2.2.4
      rationale: SATRE requires TRE operators to test changes before they are used in production. Designing TREs or TRE components with GitOps practices in mind will ensure this component is fulfilled.
    - ref: 2.2.6
      rationale: SATRE requires TRE operators to have a documented procedure for removing infrastructure when it is no longer needed. Designing TREs or TRE components with GitOps practices in mind will ensure this component is fulfilled. 
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

The K8TRE Reference Implementation uses ArgoCD installed on a management cluster to manage nearly all resources on the child cluster(s) it manages. Here "nearly all" means ArgoCD will not be responsible for creating/destroying workspaces. JupyterHub is responsible for creating/destroying workspaces.

### TREu

TREu deployments use GitOps [(e.g. for the ARC TRE, per ISMS guidance)](https://isms.arc.ucl.ac.uk/rism18-gitops_procedure/) to provision all TRE resources, as well as all infrastructure level resources, to both staging and production environments.

### FRIDGE

## FAQ

- Why is employing GitOps practices recommended?

   Using GitOps confers several advantages, but it is primarily recommended to ensure deployments are auditable. Using GitOps ensures deployments (infrastructure, applications, and configuration) are stored as declarative and version-controlled code. The Git history becomes a complete log of the TRE's state, which can help operators satisfy compliance and security requirements e.g. those of ISO 27001.
