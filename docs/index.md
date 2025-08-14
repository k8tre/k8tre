# K8TRE - A DARE TREvolution project

K8TRE is a SATRE-compliant, Kubernetes-native Trusted Research Environment (TRE) that can be deployed to any cloud-provider as well as on-prem infrastructure.

As part of the [DARE-UK](https://dareuk.org.uk/) [TREvolution](https://dareuk.org.uk/how-we-work/ongoing-activities/trevolution/) program, the K8TRE project is developing a specification for Kubernetes-native TREs as well as a reference implementation that can be deployed to [Azure Kubernetes Service](https://azure.microsoft.com/en-us/products/kubernetes-service), [Amazon Elastic Kubernetes Service](https://aws.amazon.com/eks/) and to [K3S](https://k3s.io/) on on-prem infrastructure (eg. on baremetal or VM-based environments).

## Motivations for K8TRE

The research landscape is experiencing rapid growth in secure data environments driven by increasing demand for data-driven research and analytics. Organisations are evolving from first-generation TREs (focused primarily on security) to second-generation secure data environments that support broader use cases including AI/ML research, federated analytics, and collaborative research operations.

### Current Landscape and Challenges

**Cloud Solutions: Benefits and Limitations**

Cloud providers offer robust frameworks that simplify secure data environment deployment with pre-built components for security, user management, and data transfer controls. However, several significant concerns have emerged:

- **Vendor lock-in**: Dependence on proprietary cloud services limits flexibility and can lead to unsustainable costs as organisations become tightly coupled to specific platforms
- **Cost uncertainty**: Hidden expenses from underlying cloud services can be difficult to predict and control, making budget planning challenging for research organisations
- **Development complexity**: Requiring full cloud instances for development makes it expensive and cumbersome for teams to customise and iterate on their environments

### K8TRE's Approach: Third-Generation Principles

K8TRE advocates for a "third-generation" approach to secure data environments built on three core principles:

**Open Development**: Embrace open-source approaches to foster collaboration, enable community oversight, and allow organisations to contribute as partners rather than just consumers. This promotes transparency, reduces dependency on single vendors, and enables the research community to collectively improve security and functionality.

**Cloud-Agnostic Design**: Build environments that can operate across multiple cloud providers and on-premise infrastructure, enabling organisations to leverage existing high-performance computing resources and choose cost-effective solutions that best fit their needs and constraints.

**Enhanced Developer Support**: Provide modern development tools that allow local development and testing without requiring expensive cloud deployments, making it easier for research teams to customise and extend their environments.

### Strategic Impact

The architectural decisions made today will determine organisations' ability to collaborate effectively, manage costs, and maintain technological flexibility. K8TRE emphasises the need to balance security and compliance requirements with sustainability and innovation capabilities as secure data environments scale beyond traditional research boundaries into broader data science and analytics applications.

Documentation is divided into the following sections:

- [**K8TRE Specification**](spec/README.md)
- [**K8TRE Reference Implementation**](implementation/architecture.md)
- [**K8TRE Development**](development/introduction.md)

