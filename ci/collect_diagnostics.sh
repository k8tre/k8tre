#!/usr/bin/env bash
# Collect diagnostics and logs from ArgoCD and Kubernetes resources
set +e

echo "::group::system-memory"
free -h
swapon --show || true
echo "::endgroup::"

echo "::group::argocd-server"
kubectl -n argocd logs deploy/argocd-server 2>&1 || true
echo "::endgroup::"

echo "::group::argocd-repo-server"
kubectl -n argocd logs deploy/argocd-repo-server 2>&1 || true
echo "::endgroup::"

echo "::group::argocd-application-controller"
kubectl -n argocd logs statefulset/argocd-application-controller 2>&1 || true
echo "::endgroup::"

for kind in appprojects applicationsets applications; do
  echo "::group::argocd $kind"
  kubectl describe "$kind" -A 2>&1 || true
  echo "::endgroup::"
done

for namespace in $(kubectl get namespace -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
  echo "***** $namespace *****"
  for kind in daemonset deployment statefulset ingress service pod; do
    for name in $(kubectl -n "$namespace" get "$kind" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      echo "::group::$kind/$name"
      kubectl -n "$namespace" describe "$kind/$name" 2>&1 || true
      echo "::endgroup::"
    done
  done
done

for namespace in backend cr8tor keycloak jupyterhub gateway kube-system; do
  for pod in $(kubectl -n "$namespace" get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    echo "::group::logs $namespace/$pod"
    kubectl -n "$namespace" logs "$pod" --all-containers=true --tail=100 2>&1 || true
    echo "::endgroup::"
  done
done
