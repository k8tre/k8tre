#!/bin/bash
set -e

# Print message function
print_message() {
  echo "================================================================================"
  echo ">>> $1"
  echo "================================================================================"
}

# Install dependencies
print_message "Installing system dependencies"
sudo apt-get update
sudo apt-get install -y \
  curl \
  git \
  jq \
  make \
  wget \
  unzip \
  gnupg \
  apt-transport-https \
  ca-certificates \
  software-properties-common \
  lsb-release

# Install Python dependencies
print_message "Installing Python dependencies"
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Install ArgoCD CLI
print_message "Installing ArgoCD CLI"
VERSION=$(curl -s https://api.github.com/repos/argoproj/argo-cd/releases/latest | jq -r '.tag_name')
curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/download/${VERSION}/argocd-linux-amd64
chmod +x /usr/local/bin/argocd

# Install Sealed Secrets CLI (kubeseal)
print_message "Installing Sealed Secrets CLI (kubeseal)"
KUBESEAL_VERSION=$(curl -s https://api.github.com/repos/bitnami-labs/sealed-secrets/releases/latest | jq -r '.tag_name')
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION:1}-linux-amd64.tar.gz
tar -xvzf kubeseal-${KUBESEAL_VERSION:1}-linux-amd64.tar.gz kubeseal
install -m 755 kubeseal /usr/local/bin/kubeseal
rm kubeseal kubeseal-${KUBESEAL_VERSION:1}-linux-amd64.tar.gz

# Setup K3s configuration for development
print_message "Setting up K3s development configuration"
mkdir -p /home/vscode/.kube
sudo tee /etc/rancher/k3s/config.yaml << EOF
node-name: k8tre-dev
tls-san:
  - k8tre-dev
cluster-init: true
EOF

# Add yq for YAML processing
print_message "Installing yq"
YQ_VERSION="v4.40.5"
sudo wget -qO /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
sudo chmod +x /usr/local/bin/yq

# Install k9s for easier kubectl management
print_message "Installing k9s"
K9S_VERSION=$(curl -s https://api.github.com/repos/derailed/k9s/releases/latest | jq -r '.tag_name')
curl -sL "https://github.com/derailed/k9s/releases/download/${K9S_VERSION}/k9s_Linux_amd64.tar.gz" | tar -xz -C /tmp
sudo install -m 755 /tmp/k9s /usr/local/bin/
rm /tmp/k9s

# Install kubectx and kubens
print_message "Installing kubectx and kubens"
git clone https://github.com/ahmetb/kubectx /tmp/kubectx
sudo install -m 755 /tmp/kubectx/kubectx /usr/local/bin/
sudo install -m 755 /tmp/kubectx/kubens /usr/local/bin/
rm -rf /tmp/kubectx

# Set up environment variables
print_message "Setting up environment variables"
echo "export KUBECONFIG=/home/vscode/.kube/config" >> /home/vscode/.bashrc
echo "export PATH=\$PATH:/home/vscode/.local/bin" >> /home/vscode/.bashrc

# Create aliases
cat >> /home/vscode/.bashrc << EOF

# K8TRE aliases
alias k='kubectl'
alias kns='kubens'
alias kctx='kubectx'
alias ksec='kubectl get secret'
alias kpods='kubectl get pods'
alias kdep='kubectl get deployments'
alias ksvc='kubectl get services'
alias start-k8tre='./.devcontainer/start-k8tre-dev.sh'
EOF

print_message "DevContainer setup complete! 🎉"
print_message "To start your development environment, run: ./.devcontainer/start-k8tre-dev.sh"
