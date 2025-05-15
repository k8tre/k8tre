FROM mcr.microsoft.com/vscode/devcontainers/base:ubuntu-24.04

USER root
# Install dependencies

# Kubectl, helm are enabled as features from the devcontainer.json

# Application versions

ARG ARGOCD_VERSION='3.0.0' 
ARG KUBESEAL_VERSION='0.29.0'

RUN apt-get update \
    && apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    git \
    gnupg \
    lsb-release \
    make \
    software-properties-common \
    unzip \
    wget 

# Install ArgoCD CLI
RUN curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/download/$ARGOCD_VERSION/argocd-linux-amd64  \
    && install -m 555 argocd-linux-amd64 /usr/local/bin/argocd \
    && rm argocd-linux-amd64

# Install Kubeseal CLI for use with sealed secrets
RUN curl -OL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION:?}/kubeseal-${KUBESEAL_VERSION:?}-linux-amd64.tar.gz" \
    && tar -xvzf kubeseal-${KUBESEAL_VERSION:?}-linux-amd64.tar.gz kubeseal \
    && install -m 755 kubeseal /usr/local/bin/kubeseal \
    && rm kubeseal /usr/local/bin/kubeseal