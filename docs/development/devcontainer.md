# Using the DevContainer for K8TRE Development

K8TRE now provides a Visual Studio Code DevContainer configuration to simplify setup of development environments. This guide explains how to use this feature.

## What is a DevContainer?

A Development Container (DevContainer) defines a consistent, reproducible development environment with all tools and dependencies pre-configured. This eliminates "works on my machine" issues and speeds up onboarding for new contributors.

## Prerequisites

To use the DevContainer, you'll need:

1. [Visual Studio Code](https://code.visualstudio.com/) installed on your computer
2. [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or compatible container runtime)
3. [Visual Studio Code Remote - Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

## Using the DevContainer

1. Clone the K8TRE repository:
   ```bash
   git clone https://github.com/k8tre/k8tre.git
   cd k8tre
   ```

2. Open the folder in Visual Studio Code:
   ```bash
   code .
   ```

3. When prompted, click "Reopen in Container", or use the Command Palette (F1) and select "Remote-Containers: Reopen in Container".

4. VS Code will build the DevContainer (this may take several minutes on the first run).

5. Once the container is ready, you'll have access to:
   - All required CLI tools (kubectl, kustomize, helm, argocd, etc.)
   - Proper Python environment with dependencies
   - Pre-configured Kubernetes extensions
   - K3s for local development

## Starting Development

Once inside the container:

1. The container is already configured with:
   - K3s running for local Kubernetes development
   - Kubectl configured with the proper kubeconfig
   - ArgoCD installed and ready to use

2. Apply the K8TRE resources:
   ```bash
   kubectl apply -f local/root-app-of-apps.yaml
   ```

3. Access the ArgoCD UI:
   - Set up port forwarding to access the ArgoCD UI:
     ```bash
     kubectl port-forward svc/argocd-server -n argocd 8080:443
     ```
   - Open https://localhost:8080 (or more likely https://localhost:8081 - check PORTS tab in VS Code) in your browser
   - Get the initial admin password. This is displayed at startup or run the following command.
     ```bash
     kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d; echo
     ```
   - Log in with username: admin and the password retrieved above

4. Follow the regular K8TRE development workflow

## GitHub Codespaces

The same DevContainer configuration works with GitHub Codespaces. To use it:

1. Go to the K8TRE GitHub repository
2. Click the "Code" button
3. Select the "Codespaces" tab
4. Click "Create codespace on main"

This will create a cloud-based development environment with the same configuration.

## Customizing the DevContainer

If you need to customize your development environment, you can modify:

- `.devcontainer/devcontainer.json` - Main configuration file
- `.devcontainer/post-create.sh` - Script that runs after container creation

<!-- See the [DevContainer README](.devcontainer/README.md) for more details. -->
