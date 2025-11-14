# Kind multi-cluster setup

!!! warning "DO NOT USE - Not tested yet"

https://gist.github.com/developer-guy/173347e71f92a61abbc017deb518b6cb

# Create management cluster
```bash
cat <<EOF | kind create cluster --name mgmt --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.110.0.0/16"
  serviceSubnet: "10.115.0.0/16"
nodes:
- role: control-plane
- role: worker
EOF
```

# Create dev cluster
```bash
cat <<EOF | kind create cluster --name dev --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.220.0.0/16"
  serviceSubnet: "10.225.0.0/16"
nodes:
- role: control-plane
- role: worker
EOF
```

```bash
kubectl --context kind-mgmt get nodes -o=jsonpath='{range .items[*]}{"ip route add "}{.spec.podCIDR}{" via "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
```

```bash
kubectl --context kind-dev get nodes -o=jsonpath='{range .items[*]}{"ip route add "}{.spec.podCIDR}{" via "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
```