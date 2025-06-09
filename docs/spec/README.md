# K8TRE Decisions

> [!NOTE]  
> The distinction between "the K8TRE Specification", "a K8TRE", and "the K8TRE Reference Implementation".
> The K8TRE Specification is a SATRE-conformant Specification for how a K8S TRE should be built. *A* K8TRE is an implementation of a K8TRE Specification-compliant TRE. The K8TRE Reference Implementation is the official K8TRE project's implementation of a K8TRE Specification-compliant TRE.

## GitOps using ArgoCD

*Questions*:
1. What CI/CD tool is K8TRE going to use?
2. Should the tool deploy and manage applications to the same cluster it is installed on or deploy applications to other clusters? i.e. in-cluster vs cross-cluster architecture?
3. What are the limits of what the CI/CD tool manages?

    1. Argo CD.
    2. Cross-cluster architecture supports two sub-models: 
        - deployment of K8TRE to dev/test/prod clusters from a single ArgoCD installation
        - deployment of one K8TRE per project or deployment of ephemeral K8TRE development environments for each developer.
    3. In the JupyterHub control plane model, JupyterHub is responsible for creating/destroying workspaces, not ArgoCD. ArgoCD will complain that JupyterHub is out-of-sync because of the new resources but there are ways of addressing this.

*K8TRE Reference Implementation Statement*: K8TRE will follow GitOps principles and will use ArgoCD installed on a management cluster to manage nearly all resources on the child cluster(s) it manages. Here "nearly all" means ArgoCD will not be responsible for creating/destroying workspaces.

## BYO Software 

*Questions*: 
1. What is K8TRE's stance on allowing researchers to ingress "bring-your-own software" and code, versus a curated software model? Will it allow both?

    1. If it's software that runs inside the researcher's VM/workspace, it should be up to the TRE administrators to determine what can be run. If it's software that requires additional infrastructure, then this is a different question regarding compliant interfaces and prerequisites for arbitrary infrastructure interacting with a K8TRE instance.

*K8TRE Specification Statement*: K8TRE supports both "bring-your-own" software and code curated software models, but it should be up to the TRE administrators to determine what can be run.

## K8TRE MVP

*K8TRE Reference Implementation Statement*: The K8TRE reference implementation MVP will be deployable on Azure AKS, AWS EKS, and K3S platforms, providing researcher workspaces in the form of containers, and using ArgoCD as the CI/CD tool.

*K8TRE Specification Statement*: The K8TRE specification MVP is a specification for how a K8TRE-compliant TRE should be built. It will therefore not promote a particular way to build a K8S-based TRE, but rather it will make statements that allow an implementer (of an entire TRE or a TRE component) to maximise their component's reusability in the K8TRE ecosystem.

## Design Principles

1. The K8TRE Reference Implementation will support multiple projects in the same TRE, but it should also be lightweight enough that it's trivial to run one K8TRE instance per project, with each project having it's own dedicated Kubernetes cluster and networking with additional firewalling.
2. The K8TRE Specification will define the capabilities that must be provided by the underlying Kubernetes platform.
3. microservices etc.
4. ?

## Container Runtimes

*Questions*: 
 1. What container runtime should the K8TRE Reference Implementation use?
 2. What statements about container runtimes must the K8TRE Specification make, pertaining to the capabilities that must be implemented by the underlying K8S platform?

    1. ?
    2. ?

*K8TRE Statement*:

## Prerequisite knowledge for deploying K8TRE

*Questions*: 
1. How much knowledge of Kubernetes should they have?
2. How much knowledge of ArgoCD should they have?
3. What else should they know?

## Base Infrastructure

### Secrets

*Questions*:
1. How do we store secrets in and make them available to applications on the cluster? Use k8s default secrets storage or more secure alternative backends?
2. How do we generate secrets and get them into k8s in the first place?

    1. k8s default is to store secrets unencrypted in etcd, this is not acceptable. k8s offers you the options:
        - encrypt at rest using a KMS provider and plugin to encrypt etcd. 
        - use the [secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/concepts.html) and supported provider to access external secrets store.
    2. Use existing organisation secrets manager where possible, enabling centralised management of credentials across an org.

*K8TRE Specification Statement*: storing secrets unencrypted in etcd is not acceptable. 

*K8TRE Reference Implementation Statement*: KMS provider and plugin the preferred solution for MVP.

### DNS

*Questions*:
1. What will provide in-cluster DNS?
2. Do we need to consider external DNS too - if so, what will provide this?

    1. The default CoreDNS should be fine, allows access to services by servicename.namespace without a separate DNS server.
    2. No, external DNS can probably be delegated to an organisations existing DNS server.

*K8TRE Specification Statement*: default in-cluster DNS services i.e. coreDNS sufficient. External DNS can be delegated to an organisations existing DNS server/provider.

*K8TRE Reference Implementation Statement*: For in-cluster services the default CoreDNS will be used, so clients can access services by servicename.namespace without a separate DNS server

### Load Balancers

*Questions*: 

1. Where should load balancers be used in the K8TRE Reference Implementation?
2. Should a K8TRE be permitted to disaggregate load balancing from the ingress controller, so ought the K8TRE Specification leave the choice of which off-cluster load balancer up to implementers?
3. Where should they be mandatory/optional/recommended in the Specification?

    1. ? 
    2. ? Yes - as long as there is one..?
    3. We should describe where load balancers are required in K8TRE. 

*K8TRE Specification Statement*: e.g. "There must be an off-cluster ingress load balancer - but does not have to be ingress controller-managed". or  "Services must be used to expose applications/components running in your cluster behind a single outward-facing endpoint"


*K8TRE Reference Implementation Statement*: AWS = , Azure = , K3S = ?

### Networking

*Questions*: 

1. What capabilities must a CNI must provide the cluster to be K8TRE compliant?
2. What CNI will K8TRE Reference Implementation use?
3. Should a K8TRE's CIDR be solely for in-cluster use only, or should applications/services outside the cluster also have access to the CIDR/VPC/VNET

    1. Full support for K8S Network Policies? i.e. not AWS VPC CNI or Azure CNI..?
    2. Cilium vs Calico - Cilium preferred, used in ARC TRE and FRIDGE
    3. No. A K8TRE's CIDR/VPC/VNET is solely for in-cluster use only so all external access is via the ingress/load-balancer

*K8TRE Specification Statement*: A K8TRE's CIDR/VPC/VNET is solely for in-cluster use; all external access to applications/services is via the ingress object/load-balancer.

A K8TRE's CNI must have full support for K8S Network Policies.


*K8TRE Reference Implementation Statement*: Cilium is the chosen CNI ? 
All external access to applications/services is via the ingress object/load-balancer.

### Storage

*Questions*: 

1. Which storage requirements shall the K8TRE Specification assume the underlying Kubernetes platform will provide? e.g. what storageClass definitions / providers should be recommended/mandated?
2. Which Persistent Volume Types/plugins will K8TRE Reference Implementation use?

    1. Storage classes should be defined for any K8TRE to use.
    2. AWS = , Azure = , K3S = 

*K8TRE Specification Statement*: PVCs from K8TRE components or applications should request from a set of pre-defined storage classes, not simply from the default storage class.
K8TRE-conformant storage classes must  

*K8TRE Reference Implementation Statement*: ? Use [Longhorn](https://longhorn.io/docs/1.9.0/deploy/install/install-with-kubectl/) for block distributed storage to align with FRIDGE and UCL Condenser?

### Database

*Questions*:

1. What should K8TRE Specification say about *in-cluster* DBs and what should it say about *off-cluster* DBs?
2. What is K8TRE Reference Implementation doing regarding DBs?
3. How prescriptive should K8TRE Specification be in dictating how DB's are deployed and managed on-cluster?

    1. Databases should be attached resources, explicitly referenced
    2. PostrgeSQL DB needed on-cluster as part of default deployment
    3. Be very light-touch, non-prescriptive beyond best practice & decoupled/microservice architecture.


*K8TRE Specification Statement*: K8TRE Specification-conformant apps shall allow the use of the default DB.
A K8TRE should integrate with an organisation's existing databases where appropriate.

*K8TRE Reference Implementation Statement*: The K8TRE Reference Implementation includes a default Postgres DB, for the general use of apps. 
CloudNativePG used with ArgoCD to configure and manage this  on-cluster DB.