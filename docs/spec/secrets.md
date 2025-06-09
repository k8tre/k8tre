---
topic: Secrets
date: 2025-05-30
discussion: link
k8tre-statements:
  spec: Storing secrets unencrypted in etcd is not acceptable. 
---

### Secrets

*Questions*:
1. How do we store secrets in and make them available to applications on the cluster? Use k8s default secrets storage or more secure alternative backends?
2. How do we generate secrets and get them into k8s in the first place?

    1. k8s default is to store secrets unencrypted in etcd, this is not acceptable. k8s offers you the options:
        - encrypt at rest using a KMS provider and plugin to encrypt etcd. 
        - use the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/concepts.html) and supported provider to access external secrets store.
    2. Use existing organisation secrets manager where possible, enabling centralised management of credentials across an org.

*K8TRE Reference Implementation Statement*: KMS provider and plugin the preferred solution for MVP.
