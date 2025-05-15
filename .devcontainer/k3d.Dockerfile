FROM docker:dind

USER root

# Install k3d
RUN wget -q -O - https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | sh

# Create a k3d cluster
# RUN k3d cluster create --k3s-server-arg '--disable=traefik' --k3s-server-arg '--disable=local-storage' --k3s-server-arg '--disable-network-policy' --k3s-server-arg '--disable-cloud-controller' --k3s-server-arg '--disable-selinux' --k3s-server-arg '--no-deploy=servicelb' --k3s-server-arg '--no-deploy=traefik' --k3s-server-arg '--no-deploy=local-storage' --k3s-server-arg '--no-deploy=metrics-server' --k3s-server-arg '--no-deploy=coredns' --k3s-server-arg '--no-deploy=network-policy' --k3s-server-arg '--no-deploy=cloud-controller-manager' --k3s-server-arg '--no-deploy=servicelb' --k3s-server-arg '--no-deploy=traefik'

RUN k3d cluster create k3d-mgmt