# k8tre Install Guide (single-node, public-IP, Cilium-based)

End-to-end install procedure that produces a working k8tre cluster reachable from
the public Internet — everything the upstream
[`docs/guides/installation.md`](../guides/installation.md) leaves implicit, plus
the cluster-side fixes that turned out to be necessary.

Reference target used while writing: a [StackIT](https://stackit.de) Ubuntu 24.04
VM, single node, 4 vCPU / 16 GB / 200 GB, public IP `188.34.94.28` (cloud-NAT'd
to the VM's private `enp3s0` 10.30.1.61), domain
`188.34.94.28.nip.io`.

## TL;DR — what's different from upstream

1. **Install k3s without flannel and without kube-proxy.** Cilium needs to own
   both. Upstream guide doesn't say this — the docs assume k3s default flannel
   and Cilium installed *alongside*, which produces a broken VXLAN clash.
2. **Install the full Gateway API CRD set (experimental channel v1.2.0)** —
   Cilium 1.16 looks for `grpcroutes` and `tlsroutes` CRDs and fails reconciling
   the Gateway if they are absent.
3. **Apply the manifests under [`bootstrap/`](../../bootstrap/)** before the
   ArgoCD root app-of-apps. The directory contains the patched
   `kustomize-with-envsubst-v1.0` plugin (with a variable whitelist for
   `envsubst` — see *Fixes applied / 1*) and the Cilium CCNP CRD safety copy.
4. **Bridge the cloud-NAT'd public IP to the gateway service IP.** The repo
   wires the Gateway listener to `gatewayClassName: cilium`, which creates a
   Service with a MetalLB-assigned IP on the cluster's internal subnet
   (`10.30.15.x`). On any cloud that does floating-IP NAT to the VM's primary
   private IP (StackIT, Hetzner, OVH, OpenStack…), that internal IP is
   unreachable from the outside, so a small `socat` systemd unit on the host
   bridges `0.0.0.0:80/443 → 127.0.0.1:14722` (cilium-envoy's loopback
   listener). See [*Expose the gateway on the host IP*](#5-expose-the-gateway-on-the-host-ip).
5. **Open egress for `argocd-repo-server` after Cilium is in place.** Once
   Cilium becomes the CNI, the `CiliumClusterwideNetworkPolicy` that ships
   with k8tre (`allow-pod-to-pod-via-gateway`) goes from inert to enforced,
   and the apt-get inside the `download-tools` init container of
   `argocd-repo-server` is denied egress to `deb.debian.org`.

The two repo-side fixes from earlier work
([PR #4](https://github.com/eggai-tech/k8tre/pull/4) — seaweedfs
`fullnameOverride` — and [PR #5](https://github.com/eggai-tech/k8tre/pull/5) —
`bootstrap/` + Longhorn CRD `ignoreDifferences`) are already merged into
`main` and don't need re-doing.

## Prerequisites

- One Linux amd64 host (VM or bare metal). 4 vCPU / 16 GB / 100 GB is a safe
  floor for the full stack including Longhorn.
- A public IP routed to the host (floating IP, elastic IP, anything that ends
  up DNAT'd to the VM's primary interface). SSH (22) and HTTP/HTTPS (80, 443)
  open inbound.
- A wildcard DNS name that resolves to the public IP. The simplest is `nip.io`
  — every `*.<public-ip>.nip.io` automatically resolves to `<public-ip>`. If
  you have a real domain, point a `*.<sub>` wildcard at the public IP.

## 1. Install k3s the Cilium way

`/etc/rancher/k3s/config.yaml`:

```yaml
node-name: <hostname>
tls-san:
  - <hostname>
  - <public-ip>
cluster-init: true
write-kubeconfig-mode: "0644"
flannel-backend: none           # Cilium provides the CNI
disable-network-policy: true    # Cilium provides network policy
disable-kube-proxy: true        # Cilium provides service routing
disable:
  - traefik                     # using cilium Gateway API
  - servicelb                   # using MetalLB
```

Then:

```sh
curl -sfL https://get.k3s.io | sh -
# Or, if k3s is already installed and the config changed:
sudo systemctl restart k3s
```

After the restart `kubectl get nodes` shows `NotReady` — that's expected
until Cilium is in.

## 2. Clean up any flannel leftovers

If you previously ran k3s with flannel and only later switched to
`flannel-backend: none`, the kernel keeps the old interfaces alive. Cilium
fails to bring up `cilium_vxlan` because flannel's VXLAN device still owns the
8472/udp port:

```sh
sudo ip link delete flannel.1 2>/dev/null || true
sudo ip link delete cni0      2>/dev/null || true
sudo rm -f /etc/cni/net.d/10-flannel.conflist
```

(On a brand-new install this section is a no-op.)

## 3. Install Cilium

```sh
helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
  --version 1.16.5 \
  --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=<vm-private-ip> \
  --set k8sServicePort=6443 \
  --set ipam.mode=kubernetes \
  --set ipam.operator.clusterPoolIPv4PodCIDRList='{10.42.0.0/16}' \
  --set routingMode=tunnel \
  --set tunnelProtocol=vxlan \
  --set gatewayAPI.enabled=true \
  --set l2announcements.enabled=true \
  --set externalIPs.enabled=true \
  --set hubble.enabled=false \
  --set operator.replicas=1
```

> If the agent CrashLoopBackOff's with
> `setting up vxlan device: creating vxlan device: address already in use`,
> you skipped step 2 — go back, delete `flannel.1`, restart the cilium pod.

## 4. Install Gateway API CRDs (experimental channel)

Cilium 1.16's Gateway API controller requires `grpcroutes.gateway.networking.k8s.io`
and `tlsroutes.gateway.networking.k8s.io` to be present, even if your routes
are all `HTTPRoute`. They are not in the *standard* CRD bundle — apply the
experimental one:

```sh
kubectl apply -f \
  https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/experimental-install.yaml
kubectl rollout restart deployment -n kube-system cilium-operator
```

## 5. Expose the gateway on the host IP

Once you bootstrap k8tre (step 6 below), Cilium will create a Service
`gateway/cilium-gateway-internal-gateway` of type `LoadBalancer` and MetalLB
will assign it an IP from `10.30.15.200-250` (the IP pool set by
`agnostics/loadbalancer`). That IP is on the cluster's private subnet — your
cloud's floating IP NAT routes the public IP only to the VM's primary
interface, so the LB IP is unreachable from outside.

The cilium-envoy DaemonSet (host-network) exposes the gateway listener on
**`127.0.0.1:14722`** with two filter chains:

- `transportProtocol: raw_buffer` — plain HTTP, routed by Host header.
- `transportProtocol: tls`, SNI `*.<your-domain>` — HTTPS, terminated with
  `gw-tls` (self-signed by cert-manager `selfsigned-ca` ClusterIssuer).

Install a tiny `socat` proxy on the host that forwards `0.0.0.0:80,443` to
`127.0.0.1:14722`. With SNI/Host preserved by `socat`, Envoy chooses the
right filter chain transparently.

```sh
sudo apt-get install -y socat

sudo tee /etc/systemd/system/k8tre-gateway-proxy@.service >/dev/null <<'UNIT'
[Unit]
Description=k8tre gateway TCP proxy host:%i -> cilium-envoy 127.0.0.1:14722
After=network-online.target k3s.service
Requires=k3s.service

[Service]
Type=simple
ExecStart=/usr/bin/socat -d TCP4-LISTEN:%i,fork,reuseaddr TCP4:127.0.0.1:14722
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now k8tre-gateway-proxy@80.service
sudo systemctl enable --now k8tre-gateway-proxy@443.service
```

Verify:

```sh
sudo ss -tlnp | grep -E ':80 |:443 '
# expect: socat listening on both
```

> Why `socat`, and not iptables DNAT? With `kubeProxyReplacement: true` Cilium
> processes service traffic in eBPF at the TC ingress hook on `enp3s0`, *before*
> iptables PREROUTING runs. DNAT rules in the nat table are bypassed for any
> packet whose destination is a Cilium-known LoadBalancer IP. A user-space
> proxy bound on the host network sidesteps the BPF programs entirely.

## 6. Bootstrap k8tre

```sh
git clone https://github.com/eggai-tech/k8tre.git
cd k8tre

# Argo CD itself (kustomize manifests under app_of_apps/argocd)
# follow upstream installation.md sections 1-3 for argocd install

# Cluster prerequisites (envsubst plugin with whitelist + Cilium CCNP CRD)
kubectl apply -k bootstrap/
kubectl rollout restart deployment -n argocd argocd-repo-server

# Cluster labels — adjust the MetalLB pool to match your VM's subnet
argocd cluster set in-cluster \
  --label environment=dev \
  --label secret-store=kubernetes \
  --label vendor=k3s \
  --label external-domain=<public-ip>.nip.io \
  --label external-dns=k3s \
  --label storage-class=k3s \
  --label metallb-ip-range=10.30.15.200-10.30.15.250

# Roll out the rest
kubectl apply -f app_of_apps/root-app-of-apps.yaml
```

Wait a few minutes — ArgoCD reconciles ~17 applications. `kubectl get
applications -n argocd` should converge to all `Synced` / `Healthy` (or, for
`storage-k3s-dev`, `OutOfSync` / `Healthy` due to cosmetic CRD drift we accept
via `appsets/agnostics/storage-class.yaml` `ignoreDifferences`).

## 7. Open egress for argocd-repo-server

This step exists *only* because once Cilium is the CNI, the
`CiliumClusterwideNetworkPolicy` `allow-pod-to-pod-via-gateway` (shipped by
`apps/jupyterhub/base/network_policy.yaml`) starts enforcing. Its egress
allows `cluster` but not `world`, and the `download-tools` init container of
`argocd-repo-server` does `apt-get install gettext-base` to provision the
`envsubst` binary needed by the CMP plugin.

```sh
kubectl apply -f - <<EOF
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: argocd-repo-server-egress-allow-world
  namespace: argocd
spec:
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: argocd-repo-server
  egress:
    - toEntities: [world, cluster]
    - toEndpoints:
        - matchLabels:
            k8s-app: kube-dns
      toPorts:
        - ports: [{port: "53", protocol: UDP}]
EOF
```

A cleaner long-term fix is to bake `gettext-base` (or the `envsubst` binary)
directly into the `argocd-repo-server` image / CMP sidecar so the init
container never needs internet — but for the moment the policy exception is
fine.

## 8. Verify end-to-end

```sh
# from any host on the internet
curl -k https://portal.<public-ip>.nip.io/
curl -k -I https://gitea.<public-ip>.nip.io/
curl -k -I https://jupyter.<public-ip>.nip.io/
curl -k -I https://guacamole.<public-ip>.nip.io/
```

The TLS cert is self-signed (cert-manager `selfsigned-ca` ClusterIssuer
auto-attached to the Gateway via the `cert-manager.io/cluster-issuer:
selfsigned` annotation on `gateway.yaml`), hence `-k` (or import the CA into
your trust store).

In the browser: `https://portal.<public-ip>.nip.io/` → "K8TRE Portal"
landing page with the *Login with Keycloak SSO* button.

## Fixes applied along the way

These are the issues that surfaced during the work and that are now either
committed to the repo or applied as cluster-side patches in the steps above.
Listed here for the next person who runs the install on a different cloud.

### 1. `kustomize-with-envsubst` plugin had no variable whitelist

The `kustomize-with-envsubst-v1.0` ConfigManagementPlugin originally ran
`envsubst` on the rendered output **without** a variable whitelist. `envsubst`
substitutes **every** `$VAR` token it finds; tokens not in the environment
become the empty string. This corrupted several ConfigMap-shipped configs:

- nginx variables (`$host`, `$http_upgrade`, ...) in
  `guacamole-auth-proxy-nginx-template` → `[emerg] invalid number of
  arguments in "map" directive`.
- Cilium policy name templates in `apps/jupyterhub/base/network_policy.yaml`
  → `CiliumClusterwideNetworkPolicy` rendered with `name: ""` → sync failure
  `CiliumClusterwideNetworkPolicy.cilium.io "" not found`.
- gitea init script variables (`$GITEA_*`) injected via the Helm chart's init
  ConfigMap → init container died with `mkdir: can't create directory '': No
  such file or directory`.

**Fix**: `bootstrap/argocd-cmp-plugin.yaml` runs
`envsubst '$CLUSTER_NAME $REGION $METALLB_IP_RANGE $DOMAIN $ENVIRONMENT'`
(explicit whitelist). Applied by `kubectl apply -k bootstrap/` in step 6.

### 2. `seaweedfs` Helm chart fullname template returned empty string

The seaweedfs chart's `seaweedfs.name` helper falls back to `.Chart.Name`.
When the chart is inflated through kustomize's `helmCharts:` field rather
than `helm install`, `Chart.Name` is not always populated and the helper
returns `""`. The master StatefulSet ended up with malformed args
(`-ip=.-master.X`, `-peers=-master-0.-master.X:9333`) and refused to start.

**Fix**: `fullnameOverride: seaweedfs` in
`agnostics/object-storage/k3s/base/seaweedfs-values.yaml`. Already merged
([PR #4](https://github.com/eggai-tech/k8tre/pull/4)).

### 3. `CiliumClusterwideNetworkPolicy` CRD missing

While we were still on the flannel CNI (before this guide), only the
namespaced `CiliumNetworkPolicy` CRD had been installed. Several k8tre apps
(`jupyterhub`, `default-network-policy`) ship `CiliumClusterwideNetworkPolicy`
resources, and ArgoCD couldn't apply them. The
`bootstrap/ciliumclusterwidenetworkpolicies-crd.yaml` (copied verbatim from
`cilium/cilium@v1.16.4`) used to be the safety net.

Once Cilium is installed as the cluster CNI (this guide), Cilium installs
all the CRDs itself and the bootstrap copy becomes redundant. It is still
applied by step 6 because applying a CRD that is already present is a no-op,
and keeping it in `bootstrap/` allows the same procedure to work on clusters
that run a different CNI (flannel/Calico) where the policy resources need to
exist as inert objects.

### 4. Longhorn CRDs reported as OutOfSync (cosmetic)

Seven CRDs that ship with the Longhorn Helm chart (`engineimages`, `engines`,
`instancemanagers`, `nodes`, `replicas`, `settings`, `volumes`) are reported
as `OutOfSync` by ArgoCD because the live CRDs carry
`app.kubernetes.io/managed-by: Helm` while the rendered manifest expects
ArgoCD-managed labels, and the CRDs include `default` and
`x-kubernetes-int-or-string` fields that the kube-apiserver and ArgoCD
normalize differently.

**Fix**: `ignoreDifferences` on `apiextensions.k8s.io/CustomResourceDefinition`
`/spec/versions` + `ServerSideApply=true` on
`appsets/agnostics/storage-class.yaml`. Already merged
([PR #5](https://github.com/eggai-tech/k8tre/pull/5)). This partially silences
the drift; closing it fully needs a more refined rule because the live CRDs
also differ in `metadata.labels` — captured as
[Outstanding follow-ups](#outstanding-follow-ups) item 1.

### 5. Gateway service had no programmatic external exposure

Cilium's Gateway API service is allocated a MetalLB IP on the cluster's
private subnet. On clouds where the public IP NAT lands on the VM's primary
interface, that IP is not reachable from outside. The pattern in the upstream
installation guide assumes a flat L2 network where MetalLB IPs *are* the
external IPs — true for bare metal lab setups, false for most cloud VMs.

**Fix**: the `socat` systemd unit installed in step 5 bridges the host's
`0.0.0.0:80,443` to Envoy's loopback listener (`127.0.0.1:14722`). The Envoy
listener has both HTTP and HTTPS filter chains and demultiplexes on
TLS/SNI, so a single TCP forward works for both.

## Outstanding follow-ups

1. **Refine `storage-k3s-dev` `ignoreDifferences`** so the seven Longhorn CRDs
   stop reporting `OutOfSync`. The current rule on `/spec/versions` is not
   sufficient because the drift also involves `metadata.labels`
   (`managed-by: Helm` vs `managed-by: argocd`).
2. **Bake `envsubst` into the argocd-repo-server image / CMP sidecar** so the
   `download-tools` init container doesn't need internet egress, and the
   `argocd-repo-server-egress-allow-world` CiliumNetworkPolicy from step 7
   becomes unnecessary.
3. **Reconcile `docs/guides/installation.md`** with this guide. The current
   upstream installation guide documents a `sed`-based plugin variant under a
   different ConfigMap name (`cmp-plugin`), assumes flannel+Cilium coexisting,
   and does not mention the cloud-vs-bare-metal exposure problem.
4. **`metrics-server` and `dns-monitor` pods CrashLoopBackOff** after the
   Cilium policy switch — same root cause as argocd-repo-server (egress
   denied by `allow-pod-to-pod-via-gateway`). Either add focused
   CiliumNetworkPolicy exceptions or relax the cluster-wide rule for system
   namespaces.

## Apple Silicon / Multipass notes (for local dev attempts)

The first attempt to run k8tre locally on Apple Silicon (arm64) via Multipass
hit two amd64-only images:

- `ghcr.io/k8tre/k8tre-backend:v1.1.0` — multi-arch index exists but only
  contains the amd64 manifest.
- `ghcr.io/karectl-crates/cr8tor-operator:0.1.0-beta.2` — single amd64
  manifest, no platform index.

Multipass on Apple Silicon cannot launch amd64 VMs natively. Options:

| Option | Pros | Cons |
| --- | --- | --- |
| Build arm64 versions of the two images and use them in the fork | Native performance, clean | Requires source access for both projects |
| Switch to Colima/Lima with `vmType: vz` + Rosetta | Near-native amd64 emulation | Means moving away from Multipass |
| `qemu-user-static + binfmt_misc` in the existing Multipass VM | Minimal setup change | 5–20× slower than native via QEMU TCG |
| Run on an amd64 cloud VM | Native, no emulation | Requires cloud resources (chosen path — StackIT) |

Additional Multipass-only issues that did **not** apply to the StackIT cluster:

- `argocd-repo-server` was stuck after a VM stop/start cycle because the
  `download-tools` init container hung on `apt-get update`. Resolved by force
  deleting the pod.
- The Multipass VM's 38 GB disk left Longhorn over-committed (35 GB of PVC
  requests against 22 GB free), and `gitea-shared-storage` ended up in
  `robustness: faulted, state: detached`. Not an issue on the StackIT VM
  (193 GB disk, 175 GB free).
