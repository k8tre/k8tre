#!/bin/bash
set -e

# Print message function
print_message() {
  echo "================================================================================"
  echo ">>> $1"
  echo "================================================================================"
}


# Setup K3s configuration for development
print_message "Setting up K3s development configuration"
mkdir -p /home/vscode/.kube
cp /kubeconfig/kubeconfig.yaml /home/vscode/.kube/config
sed -i 's/127\.0\.0\.1/kubernetes.default.svc.cluster.local/g' /home/vscode/.kube/config

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


# Check if ArgoCD is already installed
if ! kubectl get namespace argocd &>/dev/null; then
  print_message "Installing ArgoCD..."
  
  # Install ArgoCD
  # Create namespace
  kubectl create namespace argocd

  # Apply the customized resources
  kubectl apply -k argocd/overlays
  
  # Wait for ArgoCD to become ready
  print_message "Waiting for ArgoCD to start..."
  kubectl wait --for=condition=available --timeout=300s deployment/argocd-server -n argocd
  
  # Get the initial admin password
  INITIAL_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
  
  print_message "ArgoCD is ready!"
  echo "ArgoCD UI: http://localhost:8080"
  echo "Username: admin"
  echo "Password: $INITIAL_PASSWORD"
  
  # Port forward in background
  print_message "Setting up port forwarding for ArgoCD UI..."
  kubectl port-forward svc/argocd-server -n argocd 8080:80 &
  echo "Port forwarding started for ArgoCD UI"
else
  print_message "ArgoCD is already installed"
  
  # Start port forwarding if not already running
  if ! pgrep -f "kubectl port-forward svc/argocd-server" &>/dev/null; then
    print_message "Setting up port forwarding for ArgoCD UI..."
    kubectl port-forward svc/argocd-server -n argocd 8080:80 &
    echo "Port forwarding started for ArgoCD UI"
  fi
  
  # Check if the initial admin secret exists
  if kubectl -n argocd get secret argocd-initial-admin-secret &>/dev/null; then
    INITIAL_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
    echo "ArgoCD UI: http://localhost:8080"
    echo "Username: admin"
    echo "Password: $INITIAL_PASSWORD"
  else
    echo "ArgoCD UI: http://localhost:8080"
    echo "Username: admin"
    echo "Password: (initial admin secret has been removed, use your set password)"
  fi
fi


print_message "K8TRE Development Environment Ready!"
echo "To apply the K8TRE resources, use:"
echo "  kubectl apply -f local/root-app-of-apps.yaml"

print_message "DevContainer setup complete! 🎉"
