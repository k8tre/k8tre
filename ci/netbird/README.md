# Netbird Peer Pod

Standalone manifests to deploy a [Netbird](https://netbird.io/) peer pod for remote access to K8TRE in GitHub Actions CI or local development clusters.

---

## Accessing K8TRE in GitHub Actions CI

When running `.github/workflows/test.yaml`, the Netbird pod provides remote access to the ephemeral cluster on the runner.

### 1. Prerequisites
- Create a Netbird setup key (ephemeral or reusable) in the Netbird Admin Console.
- Add it as a GitHub Actions repository secret: `NETBIRD_SETUP_KEY`.
- Connect your local machine to Netbird: `netbird up`.

### 2. Trigger Workflow & Identify Route
- Run the workflow (via push or `workflow_dispatch`).
- In the workflow run log, note:
  - Runner IP: `NODE_IP` from the **Set hostname and domain** step.
  - Domain: `K8TRE_DOMAIN` (e.g. `<NODE_IP>.nip.io`).
  - Peer hostname: `k8tre-<GITHUB_RUN_ID>`.
- The job will sleep for 30 minutes in the **Sleep for Netbird debugging** step to allow interactive access.

### 3. Add Netbird Network Route
In Netbird Admin Console -> **Network Routes** -> **Add Route**:
- **Network Range**: `<NODE_IP>/32`
- **Routing Peer**: `k8tre-<GITHUB_RUN_ID>`
- **Distribution Groups**: Group containing your local machine (e.g. `All`)
- **Masquerade (NAT)**: Enabled

### 4. Open K8TRE in Browser
Navigate to `https://portal.<K8TRE_DOMAIN>` (e.g. `https://portal.<NODE_IP>.nip.io`).

Other services (`keycloak`, `jupyter`, `guacamole`, `gitea`, `argocd`) are accessible at `https://<service>.<K8TRE_DOMAIN>`.

### 5. (Optional) Shell Access & Host Debugging
SSH into the pod and use `nsenter` to access the runner host:
```bash
netbird ssh root@k8tre-<GITHUB_RUN_ID>
nsenter -t 1 -m -u -i -n -p -- bash
```

Cancel the workflow run in GitHub Actions when finished.

---

## Manual Deployment

```bash
kubectl create namespace netbird
kubectl create secret generic netbird-secret -n netbird --from-literal=NB_SETUP_KEY="<KEY>"
kubectl apply -k ci/netbird
```

---

## Network Policy

The `CiliumNetworkPolicy` (`netbird-access`) restricts the pod to:
- **Ingress**: WireGuard tunnel traffic from external peers and host (`world`, `host`, `remote-node`).
- **Egress**: External internet (`world`), host ports 80/443 for `*.K8TRE_DOMAIN` via Envoy (`host`, `remote-node`), and DNS (UDP/TCP 53).

---

## Teardown

```bash
kubectl delete -k ci/netbird
kubectl delete namespace netbird
```
