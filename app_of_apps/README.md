# App of Apps for K8TRE

This directory contains the root ArgoCD Application that bootstraps the entire K8TRE deployment using the "App of Apps" pattern. 

The root-app-of-apps.yaml file defines the main ArgoCD Application which then deploys the ApplicationSets in the appsets directory, managing the entire K8TRE implementation in a GitOps fashion.

This approach allows for declarative, version-controlled deployment of the entire K8TRE platform across multiple environments.



