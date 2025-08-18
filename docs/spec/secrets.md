---
topic: Secrets
last_updated: 2025-05-30
discussion: (https://github.com/orgs/k8tre/discussions/6)
k8tre_statements:
  spec: Storing secrets unencrypted in etcd is not acceptable.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

KMS provider and plugin the preferred solution for MVP.

### TREu

### FRIDGE

## FAQ

- How do we store secrets in and make them available to applications on the cluster? Use k8s default secrets storage or more secure alternative backends?
- How do we generate secrets and get them into k8s in the first place?

    - k8s default is to store secrets unencrypted in etcd, this is not acceptable. k8s offers you the options:
        - encrypt at rest using a KMS provider and plugin to encrypt etcd. 
        - use the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/concepts.html) and supported provider to access external secrets store.
    - Use existing organisation secrets manager where possible, enabling centralised management of credentials across an org.
