#!/bin/bash
set -e

# Print message function
print_message() {
  echo "================================================================================"
  echo ">>> $1"
  echo "================================================================================"
}


# Check if the initial admin secret exists
if kubectl -n argocd get secret argocd-initial-admin-secret &>/dev/null; then
  INITIAL_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
  echo "ArgoCD UI: http://localhost:8443"
  echo "Username: admin"
  echo "Password: $INITIAL_PASSWORD"
else
  echo "ArgoCD UI: http://localhost:8443"
  echo "Username: admin"
  echo "Password: (initial admin secret has been removed, use your set password)"
fi

print_message "To port-forward the ArgoCD UI, run the following command:"
echo "kubectl port-forward svc/argocd-server -n argocd 8080:443"

