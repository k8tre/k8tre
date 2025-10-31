# CI Scripts

Scripts for Continuous Integration and development automation.

## `create-ci-secrets.py`

Creates secrets in Kubernetes for use with External Secrets Operator. Automatically generates passwords and cryptographic keys from a YAML configuration file.

**Note:** TLS certificates are now managed by cert-manager and are not created by this script.

### Quick Start

```bash
# Create secrets in your cluster
uv run create-ci-secrets.py --context <kubectl-context>

# Preview changes without applying
uv run create-ci-secrets.py --context <kubectl-context> --dry-run
```

### Key Features

- Auto-generates secure passwords and cryptographic keys
- Configurable via `ci-secrets.yaml`
- Supports dry-run mode and existing secret handling
- TLS secrets are skipped (managed by cert-manager)

### Configuration Example

```yaml
secrets:
  - name: "app-secret"
    type: "generic"
    data:
      - key: "password"
        value: "{{ generate_password(32) }}"
      - key: "api-key"
        value: "{{ generate_hex_key }}"
```

### Use Case

Designed for CI environments to populate a Kubernetes secret store backend for External Secrets Operator testing, eliminating the need for cloud provider secret managers in development.

### Usage Examples

#### 1. Default behavior (skip existing secrets)

```bash
uv run create-ci-secrets.py --context k3d-dev
```

**Result**: Script will skip the secret because it already exists.

#### 2. Overwrite mode (replace entire secret)

```bash
uv run create-ci-secrets.py --context k3d-dev --overwrite
```

**Result**: Secret will be completely replaced - original keys will be lost!

#### 3. Merge mode (add new keys to existing secret)

```bash
uv run create-ci-secrets.py --context k3d-dev --merge-keys
```

**Result**: New keys will be added to the existing secret while preserving original keys.
