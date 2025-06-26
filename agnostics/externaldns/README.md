# External DNS for K8TRE

This directory contains the Kubernetes manifests for deploying External DNS within the K8TRE environment. External DNS automatically manages DNS records for Kubernetes services and ingresses based on annotations.

## Structure

- `azure/` - Azure DNS provider configuration
  - `base/` - Contains the base configuration files
  - `envs/` - Environment-specific configurations
    - `dev/` - Development environment configuration
    - `prod/` - Production environment configuration  
    - `stg/` - Staging environment configuration

## Features

External DNS in K8TRE provides:
- Automatic DNS record management for services and ingresses
- Support for Azure Private DNS zones
- Integration with Azure Workload Identity for secure authentication
- Environment-specific domain filtering
- Configurable sync policies and ownership tracking

External DNS is deployed as part of the platform agnostic components through the `appsets/agnostics/external-dns.yaml` ApplicationSet using the Bitnami External DNS Helm chart.

## Configuration

Each environment uses its own `values.yaml` file that configures:
- DNS provider settings (Azure Private DNS)
- Domain filters for the specific environment
- Azure authentication via Workload Identity
- Sync policies and ownership identifiers

## ToDo

- Each deployment will need to update the values.yaml file with the appropriate values for their organisation and environments. This will need to be setup as Kustomize patch elsewhere to avoid users having to modify these files here.