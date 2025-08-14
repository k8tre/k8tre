# Agnostics

K8TRE implements a base application plane that serves to abstract away some of the vendor-specific nuances of K8S. 
This plane also contains several common components that are required by the rest of the deployment such as applications for certificate and secret management, managing external DNS entries, etc.

Some of these components are described briefly here. 
Links are also provided for more comprehensive documentation.

## Secrets Management

K8TRE uses [External Secrets Operator (ESO)](https://external-secrets.io/) to synchronize secrets from external APIs into Kubernetes. 
ESO integrates with a large number of secret stores and keyvaults such as [Azure Key Vault](https://external-secrets.io/latest/provider/azure-key-vault/), [AWS Secrets Manager](https://external-secrets.io/latest/provider/aws-secrets-manager/) and more.
The reference implementation currently provides a simple, centralised [Kubernetes __secret store__](https://external-secrets.io/latest/provider/kubernetes/). 
K8TRE deployments may choose to implement an alternative key vault solution and integrate that with K8TRE easily as shown below for Azure Key Vault.

Applications can access the secrets in the _secret store_ by declaring `ExternalSecret` custom resources as part of their manifests. 
ESO will manage the entire lifecycle of secrets from fetching them from the secret store to deploying it into the correct namespace(s) where they are needed.

## Storage

Creating an abstraction layer for storage is particularly important due to the multiple [storage classes](https://kubernetes.io/docs/concepts/storage/storage-classes/) available within any one K8S provider as well as across multiple providers.
These storage classes provide different capabilities.
At the most basic level, disk-based storage classes (eg. hostpath-storage for baremetal clusters, default storage class for Azure Kubernetes Service) do not offer ReadWriteMany capability that applications may need.
This requires storage classes that leverage vendor-specific _Container Storage Interface (CSI)_ drivers such as [Azure Files CSI](https://learn.microsoft.com/en-us/azure/aks/azure-files-csi).
Moreover, default mount options may vary between vendors and will require standardisation.

K8TRE solves this by providing a set of storage classes that application developers can use in their manifests without having to concern themselves with the underlying technology backing the storage class. 

## Ingress

K8TRE currently implements [Ingress NGINX Controller](https://kubernetes.github.io/ingress-nginx/) and in future will offer support for the newer [Gateway API](https://kubernetes.io/docs/concepts/services-networking/gateway/).
Vendor-specific manifests are provided for Nginx. 

## DNS

Services within K8TRE are discoverable as normal through CoreDNS with the usual format of `<service-name>.<namespace>.svc.cluster.local`.
However, where services need to be exposed to external clients, an external DNS entry is required. 
There are a large number of DNS solutions such as [Azure DNS](https://learn.microsoft.com/en-us/azure/dns/public-dns-overview), [Azure Private DNS](https://learn.microsoft.com/en-us/azure/dns/private-dns-overview), [Amazon Route 53](https://aws.amazon.com/route53/), etc.

K8TRE allows applications to automatically create, update and delete DNS entries required to expose their services by using [ExternalDNS](https://kubernetes-sigs.github.io/external-dns/) as an abstraction layer over vendor-specific DNS solutions.
ExternalDNS can create DNS entries automatically using [multiple approaches](https://kubernetes-sigs.github.io/external-dns/v0.15.0/docs/faq/#how-do-i-specify-a-dns-name-for-my-kubernetes-objects). 
The simplest approach is by using the `hosts` field of the ingress object or the `external-dns.alpha.kubernetes.io/hostname` annotation on the ingress object.
