# K8TRE Installation
This guide provides instruction to quickly get K8TRE up and running on a local k8s cluster. It is structured with various entry points depending on your purpose, target machine setup and familiarity with technologies such as Kubernetes.

Before we can get cracking with K8TRE, we first need a Kubernetes (K8s) cluster available on your local host machine along with a single linux-based virtual machine to run the k8s cluster on.

!!! note
    All code blocks below coloured blue should be run on the host machine, while grey block commands should be run inside the Ubuntu VM

## Prepare VM node 
There are multiple ways to stand up and access a linux-based VM whether on a local machine or via some remote cloud resource. This guide assumes you have a local machine (Laptop?) without any existing framework for managing and deploying VMs. Although, if you already have an available framework setup (e.g. VirtualBox, VMware, etc) feel free to skip to the next section. 

To spin up a local Ubuntu-based VM follow the instructions below based on your local machine OS:

=== "MacOS"
    [Multipass](https://canonical.com/multipass) provides a simple approach to quickly spin up Ubuntu-based VMs on demand.

    1. Install Multipass by downloading the installer [here](https://canonical.com/multipass/download/macos) or using brew in Terminal:
        <div class="code-blue">
        ```shell
        brew install --cask multipass
        ```
       
    2. Check multipass is installed and accessible from terminal:
       <div class="code-blue">
        ```shell
            multipass version
        ```
        </div>
    3. Create a VM in multipass with Ubuntu 24.04. Note, you may need to adjust the VM spec based on your resource availability.
       <div class="code-blue">
        ```shell
        multipass launch 24.04 \
            --name k8tre-vm \
            --cpus 2 \
            --memory 8G \
            --disk 40G
        ```
        </div>
    4. Check the VM is up and running:
        <div class="code-blue">
        ```shell
        multipass info k8tre-vm
        ```
        </div>
        You should see output similar to:
        ```shell
        Name:           k8tre-vm
        State:          Running
        Snapshots:      0
        IPv4:           192.168.64.8
                        10.42.0.27
        Release:        Ubuntu 24.04.3 LTS
        Image hash:     267449473631 (Ubuntu 24.04 LTS)
        CPU(s):         2
        Load:           0.96 0.91 0.88
        Disk usage:     7.8GiB out of 11.5GiB
        Memory usage:   1.9GiB out of 3.8GiB
        Mounts:         --
        ```
    5. To install Kubernetes on the VM you will need to open a terminal to the VM itself. To do this run:
        <div class="code-blue">
        ```shell
        multipass shell k8tre-vm
        ```
        </div>
        
=== "Windows"

    ### Option 1: Multipass

    [Multipass](https://canonical.com/multipass) provides a simple approach to quickly spin up Ubuntu-based VMs on demand. It automatically downloads Ubuntu cloud images and handles all configuration.

    1. Install Multipass by downloading the installer [here](https://canonical.com/multipass/download/windows) or using Windows Package Manager in PowerShell:
        <div class="code-blue">
        ```powershell
            winget install Canonical.Multipass
        ```
        </div>

        !!! note
            Multipass on Windows requires either **Hyper-V** (Windows Pro/Enterprise/Education) or **VirtualBox** (works on Windows Home).

            - **Hyper-V**: Enable it in Windows Features -> Turn Windows features on or off -> Check "Hyper-V"
            - **VirtualBox**: If on Windows Home or prefer VirtualBox, install [VirtualBox](https://www.virtualbox.org/wiki/Downloads) first, then run: `multipass set local.driver=virtualbox`

    2. Check multipass is installed and accessible from PowerShell or Command Prompt:
        <div class="code-blue">
        ```powershell
            multipass version
        ```
        </div>
    3. Create a VM with Ubuntu 24.04 (this automatically downloads the Ubuntu image):
        <div class="code-blue">
        ```powershell
            multipass launch 24.04 `
                --name k8tre-vm `
                --cpus 2 `
                --memory 8G `
                --disk 40G
        ```
        </div>
        
        !!! warning "VirtualBox Network Configuration"
            When using **VirtualBox** as the driver, the VM often fails to obtain an IPv4 address. If `multipass info k8tre-vm` shows no IPv4 address, you need to specify the network adapter during VM creation.

        First, delete the VM if already created:
        <div class="code-blue">
        ```powershell
        multipass delete k8tre-vm
        multipass purge
        ```
        </div>

        Then recreate with the `--network` flag, specifying your network adapter (usually "Wi-Fi"):
        <div class="code-blue">
        ```powershell
        multipass launch 24.04 `
            --name k8tre-vm `
            --cpus 2 `
            --memory 8G `
            --disk 12G `
            --network Wi-Fi
        ```
        </div>

        To find your available network adapters, run:
        <div class="code-blue">
        ```powershell
        Get-NetAdapter | Select-Object Name, Status
        ```
        </div>

    4. Check the VM is up and running:
        <div class="code-blue">
        ```powershell
            multipass info k8tre-vm
        ```
        </div>
        You should see output similar to:
        <div class="code-blue">
        ```
        Name:           k8tre-vm
        State:          Running
        Snapshots:      0
        IPv4:           192.168.1.161
        Release:        Ubuntu 24.04.3 LTS
        Image hash:     267449473631 (Ubuntu 24.04 LTS)
        CPU(s):         2
        Load:           0.96 0.91 0.88
        Disk usage:     7.8GiB out of 11.5GiB
        Memory usage:   1.9GiB out of 3.8GiB
        Mounts:         --
        ```
        </div>
    5. Open a terminal to the VM:
        <div class="code-blue">
        ```powershell
            multipass shell k8tre-vm
        ```
        </div>

    ### Option 2: VMware Workstation

    If you prefer VMware Workstation, follow these steps:

    1. Download and install VMware Workstation Pro:
        - Visit [Broadcom VMware Downloads](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Workstation+Pro)
        - Download VMware Workstation Pro for Windows
        - Install and obtain free personal use license key

    2. Download Ubuntu 24.04 Server ISO:
        - Visit [Ubuntu Downloads](https://ubuntu.com/download/server)
        - Download Ubuntu 24.04 LTS Server ISO

    3. Create new VM in VMware:
        - Open VMware Workstation
        - File -> New Virtual Machine -> Typical
        - Select "Installer disc image file (iso)" and browse to downloaded Ubuntu ISO
        - VM Name: `k8tre-vm`
        - Disk size: 12 GB (single file)
        - Customize Hardware:
            - Memory: 8 GB
            - Processors: 2 CPUs
            - Network Adapter: NAT or Bridged

    4. Install Ubuntu:
        - Start the VM and follow Ubuntu installation wizard
        - Use default options, create user (e.g., `ubuntu`)
        - Wait for installation to complete and reboot

    5. Install VMware Tools (for better performance):
        <div class="code-blue">
        ```shell
            sudo apt update
            sudo apt install open-vm-tools
        ```
        </div>
        

    6. Access VM terminal:
        - Open the VM console in VMware Workstation, or
        - SSH to the VM using the IP shown in VMware (run `ip a` in VM to find IP)
    

## Kubernetes Cluster (K3s)
At this point, we're ready to install [K3s](https://k3s.io/), a lightweight Kubernetes cluster distribution. You should have a target VM running Ubuntu 24.04 on your local host machine (or maybe remotely) accessible via your chosen command line tool.

**1. Install K3s on the VM**

Execute the following commands in terminal to download and install K3s onto the VM:

```shell
sudo mkdir -p /etc/rancher/k3s
sudo tee /etc/rancher/k3s/config.yaml << EOF
node-name: k8tre-vm
tls-san:
  - k8tre-stg
cluster-init: true
flannel-backend: none
disable-network-policy: true
disable:
  - traefik
  - servicelb
EOF

curl -sfSL https://get.k3s.io | INSTALL_K3S_VERSION=v1.32.4+k3s1 sh -
```

**2. Cluster Access**

Ensure the logged in user (e.g. ubuntu) can access the cluster by setting the user's kube/config:
```shell
mkdir -p ~/.kube
sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc; source ~/.bashrc 
``` 
At this point you should be able to verify access to the k8s cluster using kubectl:
```shell
kubectl get pods -n kube-system
```

**3. Install Gateway API CRDs**

K8TRE uses the Kubernetes Gateway API for ingress routing. Install the Gateway API CRDs before configuring the cluster networking:

```shell
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.1.1/standard-install.yaml

```

**4. Cluster Networking**

K8TRE requires the target k8s cluster supports the Cilium container network interface (CNI) that provides modern support for network routing (e.g. cilium gateway) and access control management capabilities. The following commands install the cilium CLI on the ubuntu VM:

```shell
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
```

Then install cilium into the k3s cluster with Gateway API support and Hubble observability:
```shell
CILIUM_VERSION=1.17.5
K3S_POD_CIDR=10.42.0.0/16
cilium install --version $CILIUM_VERSION \
    --set ipam.operator.clusterPoolIPv4PodCIDRList="$K3S_POD_CIDR" \
    --set cni.chainingMode=portmap \
    --set kubeProxyReplacement=true \
    --set gatewayAPI.enabled=true \
    --set hubble.relay.enabled=true \
    --set hubble.ui.enabled=true
```

In addition, install the portmap cilium CNI plugin for hostport support:
```shell
sudo mkdir -p /opt/cni/bin/
curl -sfSL https://github.com/containernetworking/plugins/releases/download/v1.7.1/cni-plugins-linux-${CLI_ARCH}-v1.7.1.tgz | sudo tar -zxvf - -C /opt/cni/bin/ ./portmap
``` 

To ensure that Cilium is ready and configured in the cluster run:
```shell
cilium status --wait
```

### Cluster DNS
Verify that cluster DNS resolution is working correctly:
```shell
kubectl run dnsutils --image=busybox:1.28 --restart=Never -it --rm -- nslookup github.com
```

If not, your VM may be operating within a private network on your host machine. The ubuntu VM resolver config which the default coreDNS service uses to forward DNS traffic may be unreachable (e.g. 127.0.0.53) from the coreDNS pod. To correct this run:
```shell
resolvectl status
```
This will show what the underlying DNS server (NAT gateway) is being used for outbound traffic e.g.:
```shell
Link 2 (enp0s1)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.64.1
       DNS Servers: 192.168.64.1 fe80::a88f:d9ff:fe95:5e64
```
Copy the IP and edit the coreDNS config map by running:
```shell
kubectl edit configmap coredns -n kube-system
```
Then edit in the VIM text editor (Shift + I on Mac) the forwarding address i.e. change:
```shell
forward . /etc/resolv.conf
```
to:
```shell
forward . 192.168.64.1
```
Apply the changes (i.e. ESC, :wq + Enter) to coreDNS:
```shell
kubectl rollout restart deployment coredns -n kube-system
```
Then re-run to confirm cluster DNS forwarding is working: 
```shell
kubectl run dnsutils --image=busybox:1.28 --restart=Never -it --rm -- nslookup github.com
```

## ArgoCD
K8TRE follows a declarative approach to deploy all agnostic and application-level components into a target cluster from a source git repository. To manage and automate this process, K8TRE relies on ArgoCD. If ArgoCD and GitOps model is unfamiliar, we first recommand gaining a brief understanding of what Argo is and why it is central to K8TRE [here](https://argo-cd.readthedocs.io/en/stable/).

**1. Install to Cluster**

```shell
ARGOCD_VERSION=v3.1.8
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml
sleep 10
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s
```

Then install the argocd CLI tool:
```shell
sudo curl -sfSL https://github.com/argoproj/argo-cd/releases/download/$ARGOCD_VERSION/argocd-linux-${CLI_ARCH} -o /usr/local/bin/argocd
sudo chmod a+x /usr/local/bin/argocd
```

**2. Portal Access**

Expose ArgoCD (running in the k8s cluster) and provide access via the ArgoCD CLI tool and web-based management UI:
```shell
kubectl port-forward svc/argocd-server -n argocd 8080:443 --address 0.0.0.0 &
```
Before attempting to login to ArgoCD via CLI or web portal, first extract the initial password set up for the admin user:
```shell
ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
echo $ARGOCD_PASSWORD
```
To login via the CLI tool:
```shell
argocd login localhost:8080 --username=admin --password="$ARGOCD_PASSWORD" --insecure
```

To access the web UI from your host web browser use the same URL and credentials. Note, for multipass VMs, replace localhost with the allocated IP address (run multipass info k8tre-vm to view the IP):

<div class="code-blue">
```shell
https://<IP_OF_VM>:8080/
```
</div>


**3. Set Cluster Labels**

This command sets required labels on the target cluster which ArgoCD uses to ensure the correct agnostic/application configurations are applied for the given k8s distribution, in this example, definitions for k3s.

!!! note
    The `external-domain` label defines the base domain used for all K8TRE services (e.g., `keycloak.stg.k8tre.org`, `jupyter.stg.k8tre.org`). Change `k8tre.org` to your own domain name.

!!! note
    Specify a IP range for the local load balancer (metallb-ip-range) that is accessible from the bridge network your VM is bound. To check the network in use, follow the steps for your host OS below:  

To identity the IP range of the VM network run:

```shell
ip route | grep default
```

This will return the network gateway IP e.g.:
```shell
default via 172.26.64.1 dev eth0 proto dhcp src 172.26.68.121 metric 100
``` 

Using 172.26.64.1 (and assuming a 255.255.255.0 net mask) i.e. 172.26.64.0-172.26.64.255 a example subnet for metallb-ip-range could be **192.168.64.240-192.168.64.250**

```shell
argocd cluster set in-cluster \
    --label environment=stg \
    --label secret-store=kubernetes \
    --label vendor=k3s \
    --label external-domain=k8tre.org \
    --label external-dns=k3s \
    --label metallb-ip-range=<e.g. 192.168.64.240-192.168.64.250>
```

**4. Enable Kustomize Helm**

This configuration update to ArgoCD allows kustomize (which argoCD uses under the hood) to render helm charts inside a build. Several K8TRE components (e.g. external-dns) install resources using Helm charts.
```shell
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
kubectl rollout restart deployment argocd-repo-server -n argocd
```

**5. Install Custom ArgoCD Plugin**

K8TRE uses a custom ArgoCD plugin to enable environment variable substitution in Kustomize builds. This allows dynamic configuration across different environments (dev, stg, prd).

First, create the plugin configuration:
```shell
cat << EOF > cmp-plugin.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cmp-plugin
  namespace: argocd
data:
  plugin.yaml: |
    apiVersion: argoproj.io/v1alpha1
    kind: ConfigManagementPlugin
    metadata:
      name: kustomize-with-envsubst
    spec:
      version: v1.0
      generate:
        command: [sh, -c]
        args:
          - |
            # Environment variables ENVIRONMENT, DOMAIN, and METALLB_IP_RANGE are passed from ApplicationSet via plugin.env
            # ArgoCD makes them available as \$ARGOCD_ENV_<NAME> in the plugin container
            # Replace patterns: \${VAR}, .ENVIRONMENT., .DOMAIN, and standalone ENVIRONMENT/DOMAIN
            kustomize build --enable-helm --load-restrictor LoadRestrictionsNone . | \\
            sed "s|\\\${ENVIRONMENT}|\${ARGOCD_ENV_ENVIRONMENT}|g; s|\\\${DOMAIN}|\${ARGOCD_ENV_DOMAIN}|g; s|\\\${METALLB_IP_RANGE}|\${ARGOCD_ENV_METALLB_IP_RANGE}|g; s|\\.ENVIRONMENT\\.|.\${ARGOCD_ENV_ENVIRONMENT}.|g; s|\\.DOMAIN|.\${ARGOCD_ENV_DOMAIN}|g; s|^ENVIRONMENT$|\${ARGOCD_ENV_ENVIRONMENT}|g; s|^DOMAIN$|\${ARGOCD_ENV_DOMAIN}|g"
EOF

kubectl apply -f cmp-plugin.yaml
```

Then patch the ArgoCD repo-server to add the plugin sidecar:
```shell
cat << 'EOF' > add-cmp-sidecar.yaml
- op: add
  path: /spec/template/spec/containers/-
  value:
    name: cmp-kustomize-envsubst
    command:
      - /var/run/argocd/argocd-cmp-server
    image: quay.io/argoproj/argocd:v2.13.3
    securityContext:
      runAsNonRoot: true
      runAsUser: 999
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
      - mountPath: /var/run/argocd
        name: var-files
      - mountPath: /home/argocd/cmp-server/plugins
        name: plugins
      - mountPath: /tmp
        name: tmp
      - mountPath: /home/argocd/cmp-server/config/plugin.yaml
        subPath: plugin.yaml
        name: cmp-plugin
- op: add
  path: /spec/template/spec/volumes/-
  value:
    name: cmp-plugin
    configMap:
      name: cmp-plugin
EOF

kubectl patch deployment argocd-repo-server -n argocd --type=json --patch-file add-cmp-sidecar.yaml
kubectl rollout status deployment argocd-repo-server -n argocd
```


**6. Add Cilium Network Policy**

The command below adds a networking policy that allows specific argocd services egress:
 
```shell
kubectl apply -f - << 'EOF'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-argocd-egress
  namespace: argocd
spec:
  endpointSelector:
    matchExpressions:
    - key: app.kubernetes.io/name
      operator: In
      values:
      - argocd-repo-server
      - argocd-dex-server
      - argocd-notifications-controller
  egress:
  - toEntities:
    - cluster
    - host
  - toCIDR:
    - 0.0.0.0/0
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
      - port: "80"
        protocol: TCP
EOF
```

## K8TRE
You should now have a minimal VM and k3s cluster configuration (i.e. cilium, ArgoCD) to install K8TRE. To do this, we need to first configure ArgoCD to listen to the K8TRE repository that contains the agnostic/application definitions which ArgoCD will use to reconcile and deploy all specified resources in to the cluster. It is recommended that you point ArgoCD [K8TRE repository](https://github.com/k8tre/k8tre) for the purposes of this quickstart guide. However, if you plan to make changes to the vanilla K8TRE deployment, we recommend you fork it into your own git organisation and then configure ArgoCD to read from that particular repository and target revision. The K8TRE repository follows a common ArgoCD App-of-Apps pattern which is important to understand when looking to extend the base K8TRE configuration, see [here](https://medium.com/@andersondario/argocd-app-of-apps-a-gitops-approach-52b17a919a66) for more details.

**1. Add Target Repository**

Add the target K8TRE repository to argoCD:
```shell
GITHUB_ORG=k8tre
GITHUB_REPOSITORY=k8tre
GITHUB_REVISION=main
argocd repo add https://github.com/$GITHUB_ORG/$GITHUB_REPOSITORY.git
```
If the target repository is protected, ensure to also include the --username and --password arguments.


**2. Clone Target Repository**

On the VM, clone the target K8TRE argo AoA repository:
```shell
git clone -b $GITHUB_REVISION https://github.com/$GITHUB_ORG/$GITHUB_REPOSITORY.git && cd k8tre
```
Modify the default K8TRE root app-of-apps manifest so that it reads from the correct git repository and branch: 

```shell
sed -i -e "s%/k8tre%/${GITHUB_REPOSITORY}%" -e "s%main%${GITHUB_REVISION}%" app_of_apps/root-app-of-apps.yaml
```

**3. Apply K8TRE App Of Apps Manifest**

This command applies the K8TRE AoA definition into the cluster which ArgoCD will begin to reconcile resources into the k3s cluster based on the agnostic/app definitions specified in the target repository.
```shell
kubectl apply -f app_of_apps/root-app-of-apps.yaml
```
The health status of K8TRE applications can be viewed via the ArgoCD web portal (i.e. http://<localhost or IP>:8080) or via the command line using kubectl.

## Host DNS Configuration

For your host machine to resolve K8TRE service domains (e.g., `portal.stg.k8tre.org`), configure split DNS forwarding to route environment-specific domains to kare-dns.

Get the kare-dns LoadBalancer IP:
```shell
kubectl get svc kare-dns-coredns -n kare-dns
```

On your host machine, create a persistent DNS configuration matching the environment and domain from ArgoCD cluster labels:

=== "MacOS"
    <div class="code-blue">
    ```shell
    sudo mkdir -p /etc/resolver
    ```
    
    ```shell
    sudo tee /etc/resolver/stg.k8tre.org << EOF
    nameserver <kare-dns-EXTERNAL-IP>
    EOF
    ```
    Flush the cache:

    ```shell
    sudo dscacheutil -flushcache
    sudo killall -HUP mDNSResponder
    ```
    </div>
=== "Linux/Ubuntu"
    <div class="code-blue">
    ```shell
    sudo mkdir -p /etc/systemd/resolved.conf.d/
    sudo tee /etc/systemd/resolved.conf.d/k8tre.conf << EOF
    [Resolve]
    DNS=<kare-dns-EXTERNAL-IP>
    Domains=~<environment>.<domain>
    EOF
    ```

    For example, with `environment=stg` and `external-domain=k8tre.org`:
    ```shell
    sudo tee /etc/systemd/resolved.conf.d/k8tre.conf << EOF
    [Resolve]
    DNS=192.168.64.240
    Domains=~stg.k8tre.org
    EOF
    ```

    The `~` prefix enables split DNS only `stg.k8tre.org` queries forward to kare-dns, all others use upstream DNS.

    Restart systemd-resolved to apply:
    ```shell
    sudo systemctl restart systemd-resolved
    ```

    Verify the configuration by running the following command. You should see a DNS resolution entry for the config defined above.
    ```shell
    resolvectl status
    ```
    </div>

=== "Windows"
    <div class="code-blue">
    ```shell
    Get-NetAdapter
    ```
    Result: vEthernet (Default Switch) - the Hyper-V adapter

    Only queries for stg.k8tre.org go to kare-dns
    
    ```shell
    Add-DnsClientNrptRule -Namespace "stg.k8tre.org" -NameServers @("172.26.64.212")
    ```
    
    Set primary and secondary DNS servers
    Primary: kare-dns (172.26.71.210)
    Secondary: Google DNS (8.8.8.8) for other domains
    Set-DnsClientServerAddress -InterfaceAlias "vEthernet (Default Switch)" -ServerAddresses ("172.26.64.212", "8.8.8.8")

    Flush DNS cache
    
    ```shell
    ipconfig /flushdns
    ```
    Test split DNS - should resolve via kare-dns
    ```shell
    Resolve-DnsName -Name portal.stg.k8tre.org -Type A
    ```

    Result: 172.26.71.212

    Test regular DNS - should work via Google DNS:

    ```shell
    Resolve-DnsName -Name google.com -Type A
    ```
    </div>

**4. K8TRE Secrets Management**

K8TRE components can utilise its default secrets management service based on the K8s operator [External Secrets Operator](https://external-secrets.io/). This provides TRE operators with an abstraction layer to provision secrets from a range of commonly used key management solutions (e.g. Azure key Vault, AWS Secrets Manager). Out-of-the-box components in K8TRE require certain secrets to be defined and accessible in the cluster. For the purposes of this guide, we also need to create these secrets. In the K8TRE repository, we include a helper script to generate keys/secrets needed by core services running in the K8TRE deployment now running on your local machine. To generate the secrets ensure you are still in the k8tre/ repo you cloned earlier and first install [uv](https://docs.astral.sh/uv/getting-started/installation/) by running the following:


```shell
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env
```
Then execute the following command to create the secrets in the cluster:
```shell
uv run ci/create-ci-secrets.py --context default
```

You should see a confirmation output describing the secrets and keys generated.

All services shown in the ArgoCD UI portal should, after a few minutes of reconciliation, all be in a healthy (green) state.

## Next Steps

Now you have K8TRE running, why not try to access the default portal and open a K8TRE workspace:

[Access a K8TRE Analytics Workspace](workspace-access.md)

[Developing K8TRE Components](../development/developer-guide.md)

