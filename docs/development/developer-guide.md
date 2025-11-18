# K8TRE Developer Guide

This guide provides comprehensive instructions for developers to start building applications on K8TRE. It assumes you have completed the initial workspace setup as described in the [Installation Guide](installation.md).

## Prerequisites

Before starting application development on K8TRE, ensure you have a working Kubernetes cluster with K8TRE deployed. Follow the detailed [Installation Guide](installation.md) to set up:

- ✅ **Workspace Setup** - Local K3s cluster or access to AKS cluster
- ✅ **K8TRE Platform Installation** - ArgoCD, Cilium, External Secrets, CNPG operators
- ✅ **Development Tools** - git, kubectl, argocd CLI, text editor


#### Required Tools
    Ensure you have the following tools installed on your development machine:\
    - `git`\
    - `kubectl`\
    - `argocd` \
    - `Text editor` (VS Code recommended)\
    - Basic understanding of Kubernetes, Kustomize, and Helm

## Repository Structure Overview

K8TRE follows a GitOps approach with ArgoCD managing deployments. Understanding the repository structure is crucial:

```
k8tre/
├── local/                           # Local development configurations
│   └── root-app-of-apps.yaml        # Local ArgoCD root application
├── appsets/                         # ApplicationSet definitions
│   ├── app1.yaml
│   ├── app2.yaml
│   └── ...
├── apps/                            # Application manifests
│   ├── app1/
│   │   ├── base/                    # Shared base configuration
│   │   │   ├── kustomization.yaml
│   │   │   ├── postgres.yaml  
│   │   │   ├── 
│   │   └── envs/                   # Environment overlays
│   │       ├── dev/
│   │       │   ├── kustomization.yaml
│   │       │   ├── values.yaml     # Helm values
│   │       │   └── *-patch.yaml    # Kustomize patches
│   │       ├── stg/
│   │       └── prd/
├── ci/
│   ├── create-ci-secrets.py        # Secret generation
│   └── ci-secrets.yaml             # Secret definitions
└── ...
```

## Key Components

1.  **Root Application** (`local/root-app-of-apps.yaml`) points to `appsets/` directory
2.  **ApplicationSets** define templates for deploying apps across environments
3.  **ArgoCD generates Applications** from ApplicationSets based on:
    -   Git directory discovery (`apps/*/envs/*`)
    -   Cluster labels (environment, external-domain)
4.  **Applications deploy** Kustomize + Helm manifests from `apps/` directory

## Base + Environment Overlay Pattern

Applications follow a two-layer structure:

**Base Layer** (`apps/<app>/base/`):

-   Shared infrastructure resources (PostgreSQL, secrets, network policies)
-   Common configurations used across all environments
-   **Never contains Helm charts** (prevents duplicate rendering)

**Environment Layer** (`apps/<app>/envs/<env>/`):

-   Environment-specific configurations (dev, stg, prd)
-   Helm chart definitions with values
-   Kustomize patches for base resources
-   Resource limits, replica counts, image tags



#### Environment Variable Substitution

K8TRE uses a custom ArgoCD plugin (`kustomize-with-envsubst-v1.0`) to substitute environment variables in manifests.

## Branching Strategy

K8TRE follows a feature-branch workflow:

- **Main branch**: `main` - stable production code
- **Feature branches**: `feature/<initials>-<feature-name>`
- **Bug fix branches**: `bugfix/<initials>-<issue-description>`

**Example naming convention:**
- For developer John Smith working on app: `feature/js-app`
- For bug fix: `bugfix/js-gateway-routing`

## Setting Up Local Development

The initial repository setup (cloning and ArgoCD installation) was completed during the K8TRE installation process. This section focuses on configuring your local environment for application development.

### Step 1: Create Development Branches

Development on K8TRE follows a hierarchical branching strategy to isolate your work while maintaining stability of other services.

```
# Navigate to the cloned K8TRE repository
cd k8tre

# Ensure you're on the latest main branch
git checkout main
git pull origin main

# Create your feature branch from main
git checkout -b feature/<initials>-<app-name>
```
### Step 2: Configure ArgoCD for Local Development

The `local/` folder contains a specialised root application configuration that enables isolated development. Unlike the production `app_of_apps/root-app-of-apps.yaml` which deploys all applications from the main branch, the local configuration uses **selective patching** to point only your application to your development branch while keeping all other services stable.

Edit `local/root-app-of-apps.yaml`:

```
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: root-app-of-apps
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/k8tre/k8tre.git
    targetRevision: feature/<initials>-<app>  # Your local development branch
    path: appsets
    kustomize:
      patches:
        # Patch ONLY your app to track your development branch
        - target:
            kind: ApplicationSet
            labelSelector: "karectl.io/appset=<your-app>"
          patch: |-
            - op: replace
              path: /spec/generators/0/matrix/generators/0/git/revision
              value: feature/<initials>-<app>
            - op: replace
              path: /spec/template/spec/source/targetRevision
              value: feature/<initials>-<app>

        # Keep all other applications on stable main branch
        - target:
            kind: ApplicationSet
            labelSelector: "karectl.io/appset!=<your-app>"
          patch: |-
            - op: replace
              path: /spec/generators/0/matrix/generators/0/git/revision
              value: main
            - op: replace
              path: /spec/template/spec/source/targetRevision
              value: main
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```
### Step 3: Apply Local Configuration

```
# Apply the local root application
kubectl apply -f local/root-app-of-apps.yaml

# Verify ArgoCD recognises the configuration
argocd app list
```

## Creating a New Application

### 1. Application Structure

Each application follows a standard structure:

```shell
apps/<app-name>/\
├── base/                        # Base Kubernetes manifests
│   ├── kustomization.yaml       # Kustomize configuration
│   ├── deployment.yaml          # Application deployment
│   ├── service.yaml             # Kubernetes service
│   ├── gateway-route.yaml       # Gateway API route
│   ├── certificate.yaml        # TLS certificate
│   └── values.yaml              # Helm values (if using Helm)
└── envs/                        # Environment-specific overrides
    ├── dev/
    │   └── kustomization.yaml
    ├── stg/
    │   └── kustomization.yaml
    └── prd/
        └── kustomization.yaml
```

Creating a new application in K8TRE involves organising manifests into base infrastructure and environment-specific configurations.

### 1. Define Application Secrets

Before creating any manifests, define required secrets in `ci/ci-secrets.yaml`. K8TRE uses the **External Secrets Operator (ESO)** to manage secrets, separating secret storage from application deployment.

Add your application's secrets to the configuration file ci-secrets.yaml:

{% raw %}
```yaml
  #Example
  # Application admin credentials
  - name: <app>-secrets
    type: generic
    data:
      - key: admin-username
        value: "admin"
      - key: admin-password
        value: "{{ generate_password(32) }}"

  # Database credentials
  - name: <app>-db-secret
    type: generic
    data:
      - key: username
        value: "<app>_user"
      - key: password
        value: "{{ generate_password(32) }}"
      - key: database
        value: "<app>"
```
{% endraw %}

Generate the secrets in your cluster:

```
uv run ci/create-ci-secrets.py --context default
kubectl get secrets -n secret-store | grep <app>
```
**How External Secrets Work:**

1.  **Secret Storage**: Secrets are created in the `secret-store` namespace 
2.  **ExternalSecret Resources**: Define which secrets to sync and where to sync them
3.  **Target Secrets**: ESO automatically creates and maintains secrets in application namespaces
4.  **Application Usage**: Applications reference the target secrets via standard Kubernetes mechanisms


### 2. Base and envs directory
#### Base Layer - Shared Infrastructure

The `base/` folder contains infrastructure resources that are common across all environments. **Helm charts should never be placed in base** to avoid duplicate rendering issues.

#### Base Kustomization File

**`apps/<app>/base/kustomization.yaml`**

The base kustomization file serves as the manifest for all shared resources. It **must list all resource files** under the `resources` section for Kustomize to include them in the build. Files not listed here will be ignored during deployment.
```
#example
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: <app>

resources:
  - certificate.yaml
  - <app>-external-secrets.yaml
  - <app>-db-external-secret.yaml
  - postgres.yaml
  - gateway-route.yaml
  - network/cnpol-allow-from-ingress.yaml
  - network/cnpol-egress-core.yaml

# NO helmCharts section here!
# Helm charts belong in environment folders only
```
### 3. Environment Layer - Application Configuration

The `envs/` folders (`dev/`, `stg/`, `prd/`) contain configurations that vary between environments. This is where Helm charts, values, and environment-specific patches belong.

#### Environment Kustomization File

**`apps/<app>/envs/dev/kustomization.yaml`**
```
#example
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: <app>

resources:
  - ../../base  # References all base layer resources

# Helm chart definition (ONLY in environment layer)
helmCharts:
  - name: <app>
    repo: https://charts.example.com/<app>
    version: 1.0.0
    releaseName: <app>
    valuesFile: values.yaml

# Environment-specific patches
patches:
  - path: patch-deployment.yaml
    target:
      kind: Deployment
      name: <app>
```
### 4. Networking Configuration

K8TRE uses Cilium for network security, following a "default deny" approach where all traffic is blocked unless explicitly allowed. Applications require network policies to function correctly.

### Required Network Policies

Create policies in `apps/<app>/base/network/`:

**Ingress Policy** (`cnpol-allow-from-ingress.yaml`):

-   Allows traffic from the Gateway namespace to your application
-   Must specify the exact ports your application listens on

**Egress Policy** (`cnpol-egress-core.yaml`):

-   **DNS (Required)**: Allow traffic to kube-system namespace for name resolution
-   **Database**: Allow traffic to PostgreSQL/Redis using service labels
-   **External Services**: Allow traffic to external APIs or services accessed via Gateway

### 5. ApplicationSet Definition

ApplicationSets automate the deployment of your application across multiple environments. Create your ApplicationSet in the `appsets/` folder.

**`appsets/<app>.yaml`**

ApplicationSets use a **matrix generator** combining Git directory discovery with cluster label matching:

{% raw %}
```yaml
#example
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: <app>
  namespace: argocd
  labels:
    karectl.io/appset: <app>  # Critical for local development isolation
spec:
  goTemplate: true
  goTemplateOptions: ["missingkey=error"]
  generators:
    - matrix:
        generators:
          # Discovers environment directories (dev, stg, prd)
          - git:
              repoURL: https://github.com/k8tre/k8tre.git
              revision: main
              directories:
                - path: apps/<app>/envs/*

          # Matches clusters by environment label
          - clusters:
              selector:
                matchLabels:
                  environment: "{{index .path.segments 3}}"

  template:
    metadata:
      name: "{{index .path.segments 1}}-{{.nameNormalized}}"
    spec:
      project: default
      source:
        repoURL: https://github.com/k8tre/k8tre.git
        targetRevision: main
        path: "{{.path.path}}"
        plugin:
          name: kustomize-with-envsubst
          env:
            - name: ENVIRONMENT
              value: "{{.metadata.labels.environment}}"
            - name: DOMAIN
              value: "{{index .metadata.labels \"external-domain\"}}"
      destination:
        server: "{{.server}}"
        namespace: <app>
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```
{% endraw %}

## Development Workflow

### 1. Make Changes

Edit your application configurations in the appropriate files. Common changes include:
- Updating/adding helm charts for applications
- Modifying Helm values in `values.yaml`
- Adding new network policies
- Updating environment-specific configurations

### 2. Test Locally

Before committing, test your changes:

```shell
# Validate Kustomize build
kustomize build apps/<app-name>/envs/dev

# Check for syntax errors
kubectl apply --dry-run=client -k apps/<app-name>/envs/dev
```

### 3. Commit and Push
Push to the feature development branch to test via ArgoCD 

```shell\
git add .
git commit -m "feat: add <app-name> application"
git push origin feature/<initials>-<feature-name>
```

### 4. ArgoCD Sync

If you've configured ArgoCD to watch your development branch, it will automatically detect changes and sync. Otherwise, manually sync:

```shell\
argocd app sync root-app-of-apps
```

### 5. Monitor Deployment

Check application status:

```shell\
# Via kubectl
kubectl get applications -n argocd
kubectl get pods -n <app-name>

# Via ArgoCD UI
# Navigate to http://<cluster-ip>:8080
```



## Troubleshooting

### Common Issues

**ArgoCD not syncing:**
- Check repository permissions
- Verify branch name in ApplicationSet
- Check ArgoCD logs: `kubectl logs -n argocd deployment/argocd-application-controller`

**Network connectivity issues:**
- Review Cilium network policies
- Check Gateway route configuration
- Verify DNS resolution: `kubectl run debug --image=busybox -it --rm -- nslookup <service-name>`

**Application not starting:**
- Check pod logs: `kubectl logs -n <app-name> deployment/<app-name>`
- Verify resource requests/limits
- Check external secret availability

### Debug Commands

```shell\
# Check ArgoCD application status
kubectl get applications -n argocd

# View detailed application info
argocd app get <app-name>-dev

# Check network connectivity
cilium connectivity test

# Monitor network traffic
hubble observe --namespace <app-name>

# Check certificate status
kubectl get certificates -n <app-name>\
```

## Submitting Changes

### 1. Create Pull Request

Once your feature is complete and tested:
- Create a Pull Request against the main branch
- Include detailed description of changes
- Add any testing instruction

### 2. Review Process

- Code review 
- Automated tests (if configured)
- Manual testing in development environment

### 3. Merge and Deploy

After approval:
- Squash and merge to main
- ArgoCD automatically deploys to environments
- Monitor deployment status

## Next Steps

Now that you understand the basics of K8TRE development:

- Explore existing applications in apps for more examples
- Review agnostic components to understand available infrastructure
- Contribute to documentation improvements
