---
topic: Telemetry
last_updated: 2025-11-25
discussion: 
k8tre_statements:
  spec: TRE operators may prohibit the use of software that requires telemetry to function within the TRE. If they decide to allow the use of this type of software, they must identify and mitigate risks arising from such communication with external services. 
  satre:
    - ref: 2.1.9
      rationale: SATRE requires TRE operators to mitigate and record any risks introduced by the use of software in the TRE that requires telemetry to function, such as licensed commercial software must contact an external licensing server. TRE operators may prohibit this entirely, or may allow it with appropriate risk mitigation and recording, but K8TRE components that facilitate the use of such software must support TRE operators in meeting this SATRE requirement.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

### TREu

### FRIDGE

## FAQ

- **Question**

   Answer