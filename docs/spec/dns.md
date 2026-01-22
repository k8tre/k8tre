---
topic: DNS
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/5
k8tre_statements:
  spec: A TRE that deploys DNS records to allow external consumers to discover services should manage the external DNS entities together with the lifecycle operations of the corresponding services, such as deployments or upgrades. This includes removing DNS records which are no longer needed.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

Services within K8TRE are discoverable as normal through CoreDNS with the usual format of `<service-name>.<namespace>.svc.cluster.local`. Applications are allowed to automatically create, update and delete DNS entries required to expose their services by using ExternalDNS running in the clusters.

### TREu

In a TREu deployment, DNS records are not created by applications running on the cluster, rather by the administrators who manage the DNS records together with the lifecycle operations of the corresponding services.

### FRIDGE

FRIDGE conceptually follows a job execution model, whereby a frontend-TRE submits tasks to a FRIDGE instance and collects results through a well-known API. FRIDGE users may not deploy long running services for external consumption and, therefore, requires no external DNS support.  

{{ satre_link(page.meta) }}

## FAQ

- **What will provide in-cluster DNS?**

   The default CoreDNS will be suitable for most TRE implementers, since it allows access to services by servicename.namespace without a separate DNS server. A TRE implementer may use a different DNS implementation if it is necessary.
