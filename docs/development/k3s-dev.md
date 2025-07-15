# Setting up K3s all-in-one Development Environment

This documentation guides you through creating an all-in-one development environment using a single K3s cluster (ArgoCD is deployment in the same cluster as a K8TRE dev deployment).

These instructions are also used for automatically testing K8TRE in [GitHub actions](https://github.com/k8tre/k8tre/actions/workflows/test.yaml).
For more hands-on instructions with explanations see [k3s.md](k3s.md).

## Prerequisites

This assumes you already have a [Ubuntu 24.04](https://ubuntu.com/download/desktop) virtual machine.

## Configure and install K3s

Create a K3s configuration file, then install K3S.
Although most commands can be passed to the command line installer it is more convenient to define them in a [K3S configuration file](https://docs.k3s.io/installation/configuration#configuration-file).
We'll be installing Cilium, so disable the default Flannel CNI.

```bash
sudo mkdir -p /etc/rancher/k3s
sudo tee /etc/rancher/k3s/config.yaml << EOF
node-name: k8tre-dev
tls-san:
  - k8tre-dev
cluster-init: true

# Custom CNI: https://docs.k3s.io/networking/basic-network-options#custom-cni
flannel-backend: none
disable-network-policy: true
disable:
  - traefik
  - servicelb
EOF

curl -sfSL https://get.k3s.io | INSTALL_K3S_VERSION=v1.32.4+k3s1 sh -
```

Setup Kubeconfig file

```bash
mkdir -p ~/.kube
sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config
```

### Setup Cilium CNI

https://docs.cilium.io/en/stable/installation/k3s/

```bash
CILIUM_VERSION=1.17.5
CILIUM_CLI_VERSION=v0.18.4
K3S_POD_CIDR=10.42.0.0/16

curl -sfSL https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-amd64.tar.gz | sudo tar -zxvf - -C /usr/local/bin/
cilium install --version $CILIUM_VERSION --set=ipam.operator.clusterPoolIPv4PodCIDRList="$K3S_POD_CIDR" --set cni.chainingMode=portmap
```

Install portmap plugin for [hostport support](https://docs.cilium.io/en/v1.17/installation/cni-chaining-portmap/#k8s-install-portmap)

```bash
sudo mkdir -p /opt/cni/bin/
curl -sfSL https://github.com/containernetworking/plugins/releases/download/v1.7.1/cni-plugins-linux-amd64-v1.7.1.tgz | sudo tar -zxvf - -C /opt/cni/bin/ ./portmap
```

Wait for Cilium to be ready, and optionally check Cilium it's working.
```
cilium status --wait
# Uncomment if you need to verify cilium is working
# cilium connectivity test
```

### 3.2 Enable Required Add-ons

Enable hostpath-storage:

```bash
# kubectl apply -f https://raw.githubusercontent.com/helm/charts/master/stable/hostpath-provisioner/hostpath-provisioner.yaml

# Metallb is now installed by Argocd
```


## Setup ArgoCD

```bash
ARGOCD_VERSION=v3.0.6
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml
sleep 10
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s

sudo curl -sfSL https://github.com/argoproj/argo-cd/releases/download/$ARGOCD_VERSION/argocd-linux-amd64 -o /usr/local/bin/argocd
sudo chmod a+x /usr/local/bin/argocd
```

Configure ArgoCD

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443 --address 0.0.0.0 &
sleep 1

# Get the initial admin password
ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

# Login, disable certificate validation
argocd login localhost:8080 --username=admin --password="$ARGOCD_PASSWORD" --insecure
```


Mark the current cluster as the ArgoCD dev environment

```bash
argocd cluster set in-cluster \
  --label environment=dev \
  --label secret-store=kubernetes \
  --label vendor=k3s \
  --label skip-cilium=true \
  --label skip-metallb=true
argocd cluster get in-cluster
```

Configure ArgoCD for Kustomize Helm Overlays by applying a ConfigMap patch:

```bash
cat << EOF > argocd-cm-patch.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-cm
    app.kubernetes.io/part-of: argocd
data:
  kustomize.buildOptions: "--enable-helm --load-restrictor LoadRestrictionsNone"
EOF

kubectl apply -f argocd-cm-patch.yaml
```

Restart the ArgoCD repo server to apply changes:

```bash
kubectl rollout restart deployment argocd-repo-server -n argocd
```

List CRDs
```bash
kubectl get crd
```

## Create secrets for use by External Secrets Operator

```bash
uv run ci/create-ci-secrets.py --context $(kubectl config current-context)
```

## Deploy the app-of-apps

Edit the app-of-apps to point to you GitHub fork `$GITHUB_REPOSITORY` and branch/commit `$GITHUB_SHA`

```bash
sed -i -e "s%/k8tre/k8tre%/${GITHUB_REPOSITORY}%" -e "s%main%${GITHUB_SHA}%" app_of_apps/root-app-of-apps.yaml
git diff
```

Deploy the app-of-apps
```bash
kubectl apply -f app_of_apps/root-app-of-apps.yaml
```

Wait for app-of-apps to be created
```bash
sleep 60
kubectl -n argocd wait --for=jsonpath='{.status.health.status}'=Healthy application root-app-of-apps --timeout=300s
```

```bash
kubectl get appprojects -A
kubectl get applicationsets -A
kubectl get applications -A
```

Wait for applications in app-of-apps to be created
```bash
kubectl -n argocd wait --for=jsonpath='{.status.health.status}'=Healthy application --all --timeout=300s
```

```bash
kubectl get deployment -A
kubectl get daemonset -A
kubectl get crd
```

## Setup Keycloak


```bash
# Get the initial admin password
KEYCLOAK_PASSWORD=$(kubectl -nkeycloak get secret keycloak-admin-secret -o jsonpath='{.data.admin-password}' | base64 -d)
# Wait a minute to ensure Keycloak is actually ready
sleep 1m

ci/ci-setup-keycloak.py \
  --keycloak-admin=admin \
  --keycloak-password="$KEYCLOAK_PASSWORD" \
  --verify=false
```


TODO:
- Check all references to `k8tre/k8tre` and `main` are changed in all applications
- Check number of applications is as expected
- Check all applications are synchronised
- Check deployments/daemonsets etc are healthy and ready
- Playright test to login and launch workspace
