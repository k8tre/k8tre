# Storage Class Configurations for K8TRE

This directory contains Kubernetes StorageClass configurations for different infrastructure providers, enabling persistent storage capabilities in the K8TRE environment.

## Structure

- `aws/` - Storage class configurations for AWS EBS/EFS
- `azure/` - Storage class configurations for Azure Disk/File
- `k3s/` - Storage class configurations for k3s local development

These storage class configurations ensure that K8TRE applications have consistent access to persistent storage regardless of the underlying infrastructure provider.