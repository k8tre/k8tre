---
topic: DNS
date: 2025-05-30
discussion: https://github.com/orgs/k8tre/discussions/5
k8tre-statements:
  spec: The TRE may use the default in-cluster DNS services e.g. coreDNS. External DNS can be delegated to an organisation's existing DNS server/provider.  
---

{{ spec_content(page.meta) }}

**Questions**: 

1. **What will provide in-cluster DNS?**

    The default CoreDNS should be fine, since it allows access to services by servicename.namespace without a separate DNS server.

2. **Do we need to consider external DNS too - if so, what will provide this?**

    No, external DNS is delegated to an organisation's existing DNS server.
