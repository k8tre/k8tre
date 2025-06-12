---
topic: Storage
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/2
k8tre-statements:
  spec: PVCs from K8TRE components or applications should request from a set of pre-defined storage classes, not simply from the default storage class.  
  refimpl: Use [Longhorn](https://longhorn.io/docs/1.9.0/deploy/install/install-with-kubectl/) for block distributed storage to align with FRIDGE and UCL Condenser (?).
---

### Storage

*Questions*: 

1. Which storage requirements shall the K8TRE Specification assume the underlying Kubernetes platform will provide? e.g. what storageClass definitions / providers should be recommended/mandated?
2. Which Persistent Volume Types/plugins will K8TRE Reference Implementation use?

    1. Storage classes should be defined for any K8TRE to use.
    2. AWS = , Azure = , K3S = 
