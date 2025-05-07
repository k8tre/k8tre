# Keycloak for K8TRE

This directory contains the Kubernetes manifests for deploying Keycloak within the K8TRE environment. Keycloak provides identity and access management for securing the TRE infrastructure.

## Structure

- `base/` - Contains the base Kubernetes manifests for Keycloak deployment
- `envs/` - Environment-specific configurations
  - `dev/` - Development environment configuration
  - `prod/` - Production environment configuration
  - `stg/` - Staging environment configuration

Keycloak instances are deployed using the [Keycloak Operator ](https://www.keycloak.org/guides#operator) which is installed in the `keycloak` namespace from the `./base/kustomization.yaml` manifest. If different versions of the keycloak operator are required for different environments, consider moving these resources into the respective environment-specific manifests.

Keycloak depends on a Postgres database which is deployed using the [CNPG operator](https://cloudnative-pg.io/).

Database and tls secrets are stored in Git as [SealedSecrets](https://github.com/bitnami-labs/sealed-secrets).

A dummy tls secret may be created using the following script.

```bash
#!/bin/bash

# Script to create a TLS sealed secret from certificate.pem and key.pem files
host="dev.xk8tre.org"
openssl req -subj "/CN=$host/O=Test Keycloak./C=UK" -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Navigate to the script directory
cd "$(dirname "$0")"

# First create a regular secret YAML
cat > keycloak-tls-secret-temp.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-tls-secret
  namespace: keycloak
type: kubernetes.io/tls
data:
  tls.crt: $(cat certificate.pem | base64 -w 0)
  tls.key: $(cat key.pem | base64 -w 0)
EOF

# Check if kubeseal is installed
if ! command -v kubeseal &> /dev/null; then
  echo "Error: kubeseal command not found. Please install sealed-secrets."
  echo "Installation instructions: https://github.com/bitnami-labs/sealed-secrets#installation"
  exit 1
fi

# Create the sealed secret using kubeseal
kubeseal --format yaml < keycloak-tls-secret-temp.yaml > keycloak-tls-sealed-secret.yaml

# Clean up temporary files
rm keycloak-tls-secret-temp.yaml

echo "Sealed TLS secret YAML created as keycloak-tls-sealed-secret.yaml"
echo "You can safely commit this file to your repository"

# Optional: Clean up the certificate files
# Uncomment the following lines if you want to auto-remove the certificate files
# rm certificate.pem key.pem
```

The database secret can also be created in a similar manner using `kubeseal`. A sample script is provided below.

```bash
#!/bin/bash
# filepath: /home/vc/dev/k8tre/apps/keycloak/create-db-sealed-secret.sh

set -e

# Navigate to the script directory
cd "$(dirname "$0")"

# Generate a random password (16 characters)
RANDOM_PASSWORD=$(openssl rand -base64 12)

# Create a temporary file for the plain secret
cat > keycloak-db-secret-temp.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-db-secret
  namespace: keycloak
type: Opaque
stringData:
  username: keycloak-user
  password: "${RANDOM_PASSWORD}"
  database: keycloak
EOF

# Check if kubeseal is installed
if ! command -v kubeseal &> /dev/null; then
  echo "Error: kubeseal command not found. Please install sealed-secrets."
  echo "Installation instructions: https://github.com/bitnami-labs/sealed-secrets#installation"
  exit 1
fi

# Create the sealed secret using kubeseal
kubeseal --format yaml < keycloak-db-secret-temp.yaml > keycloak-db-sealed-secret.yaml

# Clean up temporary files
rm keycloak-db-secret-temp.yaml

echo "Sealed DB secret created as keycloak-db-sealed-secret.yaml"
echo "Generated password: ${RANDOM_PASSWORD}"
echo "Please store this password securely and then clear your terminal history"
echo "You can safely commit the sealed secret file to your repository"
```