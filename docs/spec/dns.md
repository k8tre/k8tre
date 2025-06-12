---
topic: DNS
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/5
k8tre-statements:
  spec: Default in-cluster DNS services i.e. coreDNS is sufficient. External DNS can be delegated to an organisation's existing DNS server/provider.  
  refimpl: For in-cluster services the default CoreDNS will be used, so clients can access services by servicename.namespace without a separate DNS server.
---

### DNS

*Questions*:
1. What will provide in-cluster DNS?
2. Do we need to consider external DNS too - if so, what will provide this?

    1. The default CoreDNS should be fine, allows access to services by servicename.namespace without a separate DNS server.
    2. No, external DNS can probably be delegated to an organisations existing DNS server.
