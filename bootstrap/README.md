# Bootstrap manifests

Cluster-scoped prerequisites that ArgoCD needs to exist before it can reconcile
the rest of the k8tre stack. Apply once after installing ArgoCD and before
applying `app_of_apps/root-app-of-apps.yaml`:

```sh
kubectl apply -k bootstrap/
kubectl rollout restart deployment -n argocd argocd-repo-server
```

## Contents

### `argocd-cmp-plugin.yaml`

The `kustomize-with-envsubst-v1.0` ConfigManagementPlugin referenced by every
ApplicationSet. The plugin renders `kustomize build --enable-helm` and then
runs `envsubst` with an **explicit variable whitelist**
(`$CLUSTER_NAME $REGION $METALLB_IP_RANGE $DOMAIN $ENVIRONMENT`).

Without the whitelist, `envsubst` substitutes every `$VAR` token it finds,
including ones that are part of generated configs (e.g. nginx variables like
`$host`, `$http_upgrade`, Cilium policy templates, gitea init scripts), turning
them into empty strings. This caused: nginx pods to fail with
`no "events" section`, `CiliumClusterwideNetworkPolicy ""` sync errors, gitea
init container failures with `mkdir -p ''`, and other downstream breakage.

### `ciliumclusterwidenetworkpolicies-crd.yaml`

`CiliumClusterwideNetworkPolicy` v2 CRD copied verbatim from
[cilium/cilium@v1.16.4](https://github.com/cilium/cilium/tree/v1.16.4/pkg/k8s/apis/cilium.io/client/crds/v2).

Several apps (`jupyterhub`, default network policies) ship
`CiliumClusterwideNetworkPolicy` resources. When Cilium is installed as the
cluster CNI the CRD is installed by Cilium itself; on clusters that use a
different CNI (e.g. k3s default flannel) the CRD has to be applied separately
so ArgoCD can sync the policy resources — they are inert in that case but the
sync no longer fails.

If you do install Cilium as your CNI, this file becomes redundant and can be
removed from the kustomization.
