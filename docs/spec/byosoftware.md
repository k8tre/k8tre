---
topic: BYO Software
last_updated: 2025-07-07
discussion: https://github.com/orgs/k8tre/discussions/8
k8tre_statements:
  spec: Both "bring-your-own software and code" and curated software models may be supported in order to provide users with the relevant tools for working with data in the TRE.
  satre:
    - ref: 2.1.10
      rationale: SATRE requires TRE operators to provide users with the relevant tools for working with data in the TRE. K8TRE components and entire TREs may fulfil this component using "bring-your-own software and code" or curated software models. The tools which should be provided will depend on the types of data in the TRE, and the expectations of users of the TRE.
---

{{ spec_content(page.meta) }}

## Implementation Compliance

### K8TRE Reference Implementation

The K8TRE Reference Implementation will be agnostic to whether a deployment supports "bring-your-own software and code" versus curated software, and will be offered with both options available via deployment configuration. It will include some example open-source applications, but expects deployments to use their own container images.

### TREu

TREu is designed for a bring-your-own software model, encouraging researchers to create Docker containers outside the TRE with required software tools, then ingress the container images into the TRE through the airlock. Pre-fabricated images are also made available to Projects via configured "global resources" (akin to a package manager).

### FRIDGE

FRIDGE extends the computational capability of another TRE by accepting tasks to run on the HPC platform where FRIDGE is deployed. Although adopting a job submission model, FRIDGE allows users to upload container images with their own software that is to be executed as a job.

{{ satre_link(page.meta) }}

## FAQ

- **What is K8TRE's stance on allowing researchers to ingress "bring-your-own software and code", versus a curated software model? Will it allow both?**

   If it's software that runs inside the researcher's VM/workspace, it should be up to the TRE administrators to determine what can be run. If it's software that requires additional infrastructure, then this is a different question regarding compliant interfaces and prerequisites for arbitrary infrastructure interacting with a K8TRE instance.
