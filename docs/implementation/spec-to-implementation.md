# K8TRE Specification To Implementation

This page documents the relationship between the K8TRE specification and the K8TRE reference implementation. 

_Work in Progress_


### BYO Software

### Container Runtimes

The K8TRE Reference Implementation uses the default high- and low-level container runtimes in the EKS, AKS, K3S Kubernetes distributions. 

### Databases

The K8TRE Reference Implementation includes the CNPG operator and a default Postgres database. Applications can deploy their own Postgres databases in a consistent manner using the operator.

### DNS

For in-cluster services, the Kubernetes default CoreDNS will be used, so clients can access services by servicename.namespace without a separate DNS server.

### GitOps

### Load Balancers

### Networking

### Secrets

### Storage