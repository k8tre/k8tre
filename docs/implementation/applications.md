# Applications

K8TRE implements a highly flexible and configurable pattern for deploying applications and microservices in a consistent manner across diverse environments. 
Microservices architecture allows K8TRE to use swappable components, add in new capabilities easily and enable or disable components as required.

The application layer of K8TRE should be deployable to any CNCF-certified Kubernetes distribution as long as the para-cluster infrastructure pre-requisites are met and the [_agnostics_ application plane](agnostics.md) can be deployed successfully. 

## KeyCloak

Keycloak is used for identity and access management in K8TRE. This Uses the Keycloak Bitnami Chart with PostgreSQL backend and External Secrets Operator for secret management.

**Dependencies**

- [CNPG Operator](https://cloudnative-pg.io/) for PostgreSQL
- [External Secrets Operator](https://external-secrets.io/) for secret synchronization

**Secret Management**

Secrets are automatically generated and managed using the CI script. To create required secrets:

```bash
# From the repository root
uv run ci/create-ci-secrets.py --context <your-kubectl-context>
```

This creates the following secrets in the `secret-store` namespace:
`keycloak-db-secret`

External Secrets Operator synchronizes these from the `secret-store` namespace into the `keycloak` namespace.

## JupyterHub

JupyterHub is used as the primary but not exclusive mechanism for provisioning researcher workspaces. _TBC_

## Backend Portal

The backend portal serves as the central authentication gateway and user interface for K8TRE.
It coordinates access between users, identity management (Keycloak), and platform applications (JupyterHub, Guacamole VDI, etc).

**What the Portal Does**

The backend portal provides a unified access point where users authenticate once and gain access to multiple research applications based on their project memberships.

When users access the portal, they authenticate via Keycloak using OIDC. The portal retrieves their user profile and queries the platform's custom resources (Users, Groups, Projects) to determine which projects and applications they can access.
Users see a dashboard listing their available projects, and within each project, the applications they're authorised to use.

**Authentication Gateway**

The portal acts as an authentication gateway for all platform services.
When users launch applications like JupyterHub or VDI, the backend issues project-scoped tokens and sets session cookies that work across the environment domain.
It implements the nginx `auth_request` pattern, validating every request to protected services by checking JWT tokens, verifying project membership, and injecting authentication headers that downstream applications can trust.

This means JupyterHub and Guacamole don't need to implement their own authentication and they receive pre-validated requests with user context headers.

**Project-Based Access Control**

Authorisation in K8TRE is project-based rather than user-based. The portal enforces this by validating that users belong to groups that have access to the requested project before allowing application access. This happens both at launch time and on every subsequent request, ensuring users can only access resources within their authorised projects.

**Application Launching**

When launching JupyterHub, the portal generates a project-scoped access token, sets appropriate session cookies, and redirects users to applications with the necessary authentication context. The portal manages token lifecycle, automatically refreshing tokens before expiry to maintain seamless sessions.

For VDI access, the portal dynamically creates VDI instance custom resources in the cluster, waits for the operator to provision the desktop environment, then generates signed Guacamole tokens with the RDP connection details. This provides users with one-click access to project-specific virtual desktops.

**Architecture**

The backend integrates multiple platform components through a workflow that handles authentication, authorisation, and service access:

![Backend Workflow Architecture](../img/backend-workflow.jpg)