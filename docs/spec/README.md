# In this folder

Each markdown file in this folder contains K8TRE Specification and K8TRE Reference Implementation statements, formatted using YAML front matter. They have been derived from the [k8tre GitHub Org Discussions](https://github.com/orgs/k8tre/discussions). The status of these statements is reflected in the table below:

| Topic                                       | Discussion Link                              | Status |
|---------------------------------------------|----------------------------------------------|--------|
| [BYO Software](./byosoftware.md)            | https://github.com/orgs/k8tre/discussions/8  | Draft  |
| [Container Runtimes](./containerruntimes.md)| https://github.com/orgs/k8tre/discussions/12 | Draft  |
| [Database](./database.md)                   | https://github.com/orgs/k8tre/discussions/9  | Draft  |
| [DNS](./dns.md)                             | https://github.com/orgs/k8tre/discussions/5  | Draft  |
| [GitOps](./gitops.md)                       | https://github.com/orgs/k8tre/discussions/7  | Draft  |
| [Load Balancers](./loadbalancers.md)        | https://github.com/orgs/k8tre/discussions/3  | Draft  |
| [Networking](./networking.md)               | https://github.com/orgs/k8tre/discussions/4  | Draft  |
| [Secrets](./secrets.md)                     | https://github.com/orgs/k8tre/discussions/6  | Draft  |
| [Storage](./storage.md)                     | https://github.com/orgs/k8tre/discussions/2  | Draft  |


> [!NOTE]  
> The distinction between "the K8TRE Specification", "a K8TRE", and "the K8TRE Reference Implementation".
> The K8TRE Specification is a SATRE-conformant Specification for how a K8S TRE should be built. *A* K8TRE is an implementation of a K8TRE Specification-compliant TRE. The K8TRE Reference Implementation is the official K8TRE project's implementation of a K8TRE Specification-compliant TRE.

# Additional Decisions
## K8TRE MVP

*K8TRE Reference Implementation Statement*: The K8TRE reference implementation MVP will be deployable on Azure AKS, AWS EKS, and K3S platforms, providing researcher workspaces in the form of containers, and using ArgoCD as the CI/CD tool.

*K8TRE Specification Statement*: The K8TRE specification MVP is a specification for how a K8TRE-compliant TRE should be built. It will therefore not promote a particular way to build a K8S-based TRE, but rather it will make statements that allow an implementer (of an entire TRE or a TRE component) to maximise their component's reusability in the K8TRE ecosystem.

## Design Principles

1. The K8TRE Reference Implementation will support multiple projects in the same TRE, but it should also be lightweight enough that it's trivial to run one K8TRE instance per project, with each project having it's own dedicated Kubernetes cluster and networking with additional firewalling.
2. The K8TRE Specification will define the capabilities that must be provided by the underlying Kubernetes platform.
3. Decoupled, microservice-like archtiecture
4. 

## Prerequisite knowledge for deploying K8TRE

*Questions*: 
1. How much knowledge of Kubernetes should they have?
2. How much knowledge of ArgoCD should they have?
3. What else should they know?
