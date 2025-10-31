# Installation Guide

**AI Generated placeholder text - Not sanity checked!**

This guide explains how to install K8TRE.

## Prerequisites

Before installing, ensure you have:

- Kubernetes cluster v1.20+
- kubectl installed and configured
- Helm v3+ (optional)

## Installation Methods

### Method 1: Using kubectl

```bash
# Apply the manifest directly
kubectl apply -f https://github.com/k8tre/k8tre/releases/latest/download/k8tre.yaml
```

### Method 2: Using Helm

```bash
# Add the Helm repository
helm repo add k8tre https://k8tre.github.io/k8tre/charts

# Update repositories
helm repo update

# Install the chart
helm install k8tre k8tre/k8tre
```

## Verifying the Installation

To verify that K8TRE is installed correctly:

```bash
kubectl get pods -n k8tre-system
```

You should see the K8TRE pods running.
