# K8TRE DevContainer Setup

This directory contains configuration for a Visual Studio Code DevContainer that provides a consistent development environment for K8TRE. The DevContainer includes all the necessary tools and dependencies to work effectively with the project.

## Features

- Pre-installed command line tools:
  - kubectl
  - helm
  - kustomize
  - ArgoCD CLI
  - kubeseal (for Sealed Secrets)
  - k3s (for local development)

- VS Code Extensions:
  - Kubernetes Tools
  - YAML Support
  - Python
  - Docker
  - GitHub Copilot
  - Remote Containers

- Configured environment:
  - Python 3.11 with required dependencies
  - Pre-configured K3s setup
  - Docker-in-Docker support

## Getting Started

1. Ensure you have [Visual Studio Code](https://code.visualstudio.com/) and the [Remote - Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension installed.

2. Open the K8TRE repository in VS Code.

3. When prompted, click "Reopen in Container" or use the Command Palette (F1) and select "Remote-Containers: Reopen in Container".

4. Wait for the container to build and initialize. This may take several minutes on the first run.

5. Once the container is ready, you can:
   - Start K3s: `sudo k3s start`
   - Set up ArgoCD: Run the setup script from `local/scripts/argocd-install.sh`
   - Begin development!

## Customization

To customize this DevContainer:

1. Modify `.devcontainer/devcontainer.json` to add or remove features, extensions, or settings.
2. Edit `.devcontainer/post-create.sh` to change the setup steps that run after container creation.

## Troubleshooting

- If K3s fails to start, check the logs: `sudo journalctl -u k3s`
- If you encounter permission issues, try running commands with `sudo`
- For ArgoCD issues, check logs: `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server`
