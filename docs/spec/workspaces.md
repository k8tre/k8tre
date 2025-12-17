---
topic: Workspaces
last_updated: 2025-11-25
discussion: 
k8tre_statements:
  spec: Project workspaces must be isolated from each other and the internet to prevent unauthorised access to data and resources, regardless of the underlying infrastructure. Intra-project shared services must only be accessible to users within the same project.
  satre:
    - ref: 2.1.8
      rationale: SATRE requires TRE operators to ensure that any shared services are only available to users working on the same project, so K8TRE components which facilitate shared services must support this project-level isolation.
    - ref: 2.1.14
      rationale: SATRE requires TRE operators to maintain segregation of users and data from different projects when using "non-standard compute". This might be scheduled HPC or GPU resources which might not provided to users by default, since these resources are often limited and shared.
    - ref: 2.2.10
      rationale: SATRE requires TRE operators to disallow connectivity between users in different projects, so K8TRE components must support this project-level isolation.
    - ref: 2.2.11
      rationale: SATRE requires TRE operators to block outbound connections to the internet by default, so K8TRE components must support this project-level isolation.  
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

### TREu

In TREu, Projects are isolated from each other at the network level, preventing inter-project transfers. Different projects use separate file systems and are mounted exclusively into project desktops, available only to the users of that project. TREu does not currently support the provision of shared services within Projects.

### FRIDGE

{{ satre_link(page.meta) }}

## FAQ

- **Question**

   Answer