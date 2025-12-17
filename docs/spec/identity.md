---
topic: Identity and Access
last_updated: 2025-11-25
discussion: 
k8tre_statements:
  spec: The TRE must implement identity and access management services to manage user access to resources based on trusted identities. These services may be deployed on-cluster, or apps may connect to off-cluster identity services, for authentication and authorisation, with MFA enforced.
  satre:
    - ref: 1.5.3
      rationale: SATRE requires TRE operators to have a set of services to manage access to resources based on identity. K8TRE-compliant components or entire TREs must therefore provide access to resources based on identity.
    - ref: 1.5.5
      rationale: SATRE requires TRE operators to have robust and secure applications in place to authenticate users (and services) within the TRE. K8TRE-compliant components or entire TREs must therefore authenticate users and services within the TRE.
    - ref: 1.5.6
      rationale: SATRE requires TRE operators to give each user of the TRE a unique logon, with changes to any records strictly controlled. K8TRE-compliant components or entire TREs must therefore follow this authentication model. 
    - ref: 3.2.4
      rationale: SATRE requires TRE operators to ensure that multi-factor authentication is enabled for all users. Identity and access management systems provided by K8TRE-compliant components or entire TREs must therefore enforce multi-factor authentication for all users.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

### TREu

TREu requires users to log into the TRE Portal using their standard UCL identity. External collaborators invited to join projects are provisioned with a guest UCL user identity during the TRE onboarding process and log in using this identity.

### FRIDGE

{{ satre_link(page.meta) }}

## FAQ

- **Question**

   Answer

