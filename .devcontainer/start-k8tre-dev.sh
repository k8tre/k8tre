#!/bin/bash
set -e

# Print message function
print_message() {
  echo "================================================================================"
  echo ">>> $1"
  echo "================================================================================"
}

# Make sure K3s is running
if ! systemctl is-active --quiet k3s; then
  print_message "Starting K3s..."
  sudo systemctl start k3s
  sleep 10
fi

# Configure kubectl
if [ ! -f ~/.kube/config ]; then
  print_message "Setting up kubeconfig..."
  mkdir -p ~/.kube
  sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config
  sudo chown $(id -u):$(id -g) ~/.kube/config
fi

# Check if ArgoCD is already installed
if ! kubectl get namespace argocd &>/dev/null; then
  print_message "Installing ArgoCD..."
  
  # Run the ArgoCD installation script
  bash $(pwd)/local/scripts/argocd-install.sh
  
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
