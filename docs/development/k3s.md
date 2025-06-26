# Setting up K3s Development Environment

This documentation guides you through creating a development environment using K3s.
Alternative approaches include KinD, vCluster, and others.

## Overview

This guide will help you set up two Ubuntu 24.04 VMs with K3s:
- A **management cluster** with ArgoCD installed
- A **development cluster** registered with ArgoCD for application deployment

ArgoCD on the management cluster will deploy and manage applications on the development cluster.

## Prerequisites

- [Ubuntu 24.04](https://ubuntu.com/download/desktop) on your local development machine
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) (with kustomize)
- [ArgoCD CLI](https://argo-cd.readthedocs.io/en/stable/cli_installation/)
- [Helm](https://helm.sh/docs/intro/install/)
- [QEMU/KVM and Virtual Machine Manager](https://ubuntu.com/blog/kvm-hyphervisor)

## Step 1: Creating Virtual Machines

### 1.1 Create Two VMs

Create two identical VMs (QEMU/KVM based) using Virtual Machine Manager:

1. Open Virtual Machine Manager
2. Click "Create new virtual machine"
3. Select "Local install media" and choose Ubuntu 24.04 ISO
4. Configure with at least 2 CPUs, 4GB RAM, and 20GB storage
5. Complete the installation process for both VMs

### 1.2 Set Hostname and Hosts

Name the VMs `vm-mgmt` and `vm-dev` respectively by editing these files:

```bash
# On the management VM
sudo nano /etc/hostname
# Change to: vm-mgmt

sudo nano /etc/hosts
# Add: 127.0.1.1 vm-mgmt

sudo hostnamectl set-hostname vm-mgmt
sudo reboot

# On the development VM
sudo nano /etc/hostname
# Change to: vm-dev

sudo nano /etc/hosts
# Add: 127.0.1.1 vm-dev

sudo hostnamectl set-hostname vm-dev
sudo reboot
```

## Step 2: Network Configuration

### 2.1 Create a Static Network

Create a new network in Virtual Machine Manager with static IP addresses:

1. Open Virtual Machine Manager
2. Go to Edit → Connection Details → Virtual Networks → +
3. Or create the network XML file directly:

```xml
<network connections="2">
  <name>static-network</name>
  <uuid>0f73f3fd-38f6-4e72-aa94-7984c2606054</uuid>
  <forward mode="nat">
    <nat>
      <port start="1024" end="65535"/>
    </nat>
  </forward>
  <bridge name="virbr1" stp="on" delay="0"/>
  <mac address="52:54:00:4f:af:6c"/>
  <domain name="xk8tre.org"/>
  <ip address="192.168.123.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.123.2" end="192.168.123.254"/>
      <host mac="52:54:00:c8:e0:2f" name="dev" ip="192.168.123.62"/>
      <host mac="52:54:00:07:36:8a" name="mgmt" ip="192.168.123.52"/>
    </dhcp>
  </ip>
</network>
```

> **Note:** The IP address `192.168.123.1` refers to your host machine's IP on this virtual network.

### 2.2 Attach VMs to Network

1. Edit each VM's configuration
2. Change the network interface to the newly created static-network
3. Make sure the MAC addresses match those specified in the network XML
4. Restart the VMs so they get their new IP addresses

## Step 3: Installing and Configuring K3s

### 3.1 Install K3s

Install K3s on both VMs:

Disable flannel and network policy as Cilium does this as part of k8tre.
Diable traefik as k8tre uses nginx for ingress
Disable servicelb as we will need metallb to provide an 'external loadbalancer'.

However, note that metallb will not work on cloud providers.


```bash
# On both VMs
curl -sfL https://get.k3s.io | sh - --flannel-backend=none --disable-network-policy --disable=traefik --disable=servicelb
sudo usermod -aG docker $USER
newgrp docker
```


### 3.2 Enable Required Add-ons

Enable MetalLB and hostpath-storage on both VMs:

```bash
# On both VMs
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.15.2/config/manifests/metallb-native.yaml
kubectl apply -f https://raw.githubusercontent.com/helm/charts/master/stable/hostpath-provisioner/hostpath-provisioner.yaml
```

See https://metallb.universe.tf/configuration/ and https://metallb.universe.tf/configuration/k3s/ for more details on setting up metallb on k3s.

Metallb needs to be configured with an IP address pool which needs to be _advertised'.

For instance, 

```yaml
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: default-pool 
  namespace: metallb-system
spec:
  addresses:
  - 192.168.123.50-192.168.123.100
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: default-advertisement
  namespace: metallb-system
spec:
  ipAddressPools:
  - default-pool
```

Create a yaml file with the above configuration and apply to your cluster. 

**This is a temporary workaround while we integrate this into the ArgoCD workflow for k3s.**

## Step 4: Export and Merge Kubeconfig

### 4.1 Export Kubeconfig from VMs

```bash
# On the management VM
k3s kubectl config view --raw > ~/.kube/config

# On the development VM
k3s kubectl config view --raw > ~/.kube/config
```

### 4.2 Copy Kubeconfig Files to Host

```bash
# From your host machine
scp <username>@192.168.123.52:~/.kube/config ~/.kube/mgmt-config
scp <username>@192.168.123.62:~/.kube/config ~/.kube/dev-config
```

### 4.3 Edit and Merge Kubeconfig Files

Edit each kubeconfig file to rename clusters and users:

```bash
# Edit mgmt-kubeconfig.yaml to change:
# - cluster name to "k3s-mgmt" 
# - user name to "admin-mgmt"

# Edit dev-kubeconfig.yaml to change:
# - cluster name to "k3s-dev"
# - user name to "admin-dev"
```

Then merge them:

```bash
KUBECONFIG=~/.kube/config:~/.kube/mgmt-config:~/.kube/dev-config kubectl config view --flatten > ~/.kube/merged-config
mv ~/.kube/merged-config ~/.kube/config
chmod 600 ~/.kube/config
```

## Step 5: Setting Up ArgoCD

### 5.1 Install ArgoCD on Management Cluster

```bash
# Switch to management cluster context
kubectl config use-context k3s-mgmt

# Create namespace
kubectl create namespace argocd

# Install ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for all pods to be ready
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s
```

### 5.2 Access ArgoCD UI

```bash
# Port-forward ArgoCD server (run this in a separate terminal)
kubectl port-forward svc/argocd-server -n argocd 8080:443 --address 0.0.0.0

# Get the initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

Visit [https://localhost:8080](https://localhost:8080) to access the ArgoCD UI.

### 5.3 Configure ArgoCD CLI

```bash
# Login to ArgoCD from your host
argocd login localhost:8080

# Or if you've set up /etc/hosts entries:
argocd login mgmt.xk8tre.org:8080
```

### 5.4 Register Development Cluster with ArgoCD

```bash
# Add the development cluster to ArgoCD
argocd cluster add k3s-dev --name dev --label environment=dev
```

### 5.5 Configure ArgoCD for Kustomize Helm Overlays

Create and apply a ConfigMap patch:

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

Learn more about [ArgoCD configuration options](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/).

## Step 6: Convenience Configurations

### 6.1 Context-Switching Aliases

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# For easy context switching
alias kdev='kubectl config use-context k3s-dev'
alias kmgmt='kubectl config use-context k3s-mgmt'

# Optionally add kubectl aliases
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
```

Then source your file: `source ~/.bashrc`

### 6.2 Host File Entries

Add the following entries to `/etc/hosts` on your host machine:

```bash
sudo bash -c 'cat << EOF >> /etc/hosts
# VMs running K3s
192.168.123.52 mgmt.xk8tre.org
192.168.123.62 dev.xk8tre.org
EOF'
```

> **Note:** Be careful not to assign IP addresses that might conflict with other devices on your network.

## Step 7: Verification

### 7.1 Test Cluster Access

```bash
# Test management cluster
kmgmt
kubectl get nodes

# Test development cluster
kdev
kubectl get nodes
```

### 7.2 Verify ArgoCD Setup

```bash
# Check that ArgoCD can communicate with both clusters
argocd cluster list
```

## Additional Resources

- [K3s Documentation](https://rancher.com/docs/k3s/latest/en/)
- [Kubernetes Documentation](https://kubernetes.io/docs/home/)
- [ArgoCD Documentation](https://argo-cd.readthedocs.io/en/stable/)
- [Helm Documentation](https://helm.sh/docs/)
- [Kustomize Documentation](https://kubectl.docs.kubernetes.io/guides/introduction/kustomize/)

## Troubleshooting

If you encounter issues:

1. Check cluster status: `k3s kubectl get nodes`
2. View K3s logs: `journalctl -u k3s`
3. Check ArgoCD logs: `kubectl logs -n argocd deployment/argocd-server`
4. For networking issues, verify the VM network configuration.
