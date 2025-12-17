---
topic: Storage
last_updated: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/2
k8tre_statements:
  spec: PVCs from K8TRE components or applications should request from a set of pre-defined storage classes, not simply from the default storage class.  
---

{{ spec_content(page.meta) }}

## Motivation

The development of K8TRE-compliant components (e.g. apps) will be facilitated by the availability of storage in the deployment whose quality-of-service, backup policies and access modes (for example) are encoded in terms of standard Kubernetes abstractions. This will allow deployers to  match up and verify component requirements against available storage.

## Implementation Compliance

### K8TRE Reference Implementation

K8TRE uses [Longhorn](https://longhorn.io/) for highly available, Kubernetes-native, distributed block storage.

### TREu

The TREu System plane cluster, which does not have access to sensitive data, uses the default storage class to provision volumes from the underlying compute platform (e.g. EBS in AWS). Project storage isolation is enacted at the compute platform level, e.g. using separate EFS file systems in AWS.

### FRIDGE

FRIDGE uses Longhorn for compatibility across different HPC platforms. FRIDGE also applies encryption on storage volumes attached to Kubernetes Pods where user jobs are exectuded, ensuring data safety.

{{ satre_link(page.meta) }}

## FAQ

- Which storage requirements shall the K8TRE Specification assume the underlying Kubernetes platform will provide? e.g. what storageClass definitions / providers should be recommended/mandated?

- Which Persistent Volume Types/plugins will K8TRE Reference Implementation use?

    Storage classes should be defined for any K8TRE to use.
