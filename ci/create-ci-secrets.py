#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#   "kubernetes>=29.0.0",
#   "typer>=0.16.0",
#   "pyyaml>=6.0.0",
#   "cryptography>=45.0.3",
# ]
# ///
"""
CI Secrets Management for External Secrets Operator

This script creates Kubernetes secrets in a secret-store namespace for use with
External Secrets Operator in CI environments. It reads configuration from
secrets.yaml and generates necessary passwords and certificates automatically.

Usage:
    uv run create-ci-secrets.py --context k3d-dev [--dry-run] [--namespace secret-store]
    python create-ci-secrets.py --context k3d-dev [--dry-run] [--namespace secret-store]
"""

import base64
import datetime
import secrets
import string
import sys
from pathlib import Path
from typing import Annotated, Any, Dict

import typer
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from rich.console import Console
from rich.table import Table

console = Console()


class SecretGenerator:
    """Generates various types of secrets and certificates."""

    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate a random password."""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_hex_key(length: int = 32) -> str:
        """Generate a random hex key."""
        return secrets.token_hex(length)

    @staticmethod
    def generate_self_signed_cert(hostname: str, days: int = 365) -> tuple[str, str]:
        """Generate a self-signed certificate and return (cert, key) as strings using cryptography."""

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CI Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now())
            .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        cert_content = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_content = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return cert_content, key_content


class CISecretsManager:
    """Manages creation of CI secrets for External Secrets Operator."""

    def __init__(
        self,
        context: str,
        namespace: str = "secret-store",
        dry_run: bool = False,
        overwrite: bool = False,
    ):
        self.context = context
        self.namespace = namespace
        self.dry_run = dry_run
        self.overwrite = overwrite
        self.generator = SecretGenerator()
        self.generated_values = {}
        self.existing_secrets = []
        self.overwritten_secrets = []
        self.skipped_secrets = []

        # Initialize Kubernetes client
        try:
            config.load_kube_config(context=context)
            self.v1 = client.CoreV1Api()
        except Exception as e:
            console.print(
                f"[red]Error: Failed to load kubectl context '{context}': {e}[/red]"
            )
            sys.exit(1)

    def load_secrets_config(self, config_path: str = "secrets.yaml") -> Dict[str, Any]:
        """Load secrets configuration from YAML file."""
        try:
            config_file = Path(__file__).parent / config_path
            with open(config_file, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            console.print(
                f"[red]Error: Configuration file '{config_path}' not found[/red]"
            )
            sys.exit(1)
        except yaml.YAMLError as e:
            console.print(f"[red]Error: Invalid YAML in '{config_path}': {e}[/red]")
            sys.exit(1)

    def ensure_namespace(self):
        """Ensure the target namespace exists."""
        if self.dry_run:
            console.print(f"[yellow]Would create namespace: {self.namespace}[/yellow]")
            return

        try:
            self.v1.read_namespace(name=self.namespace)
            console.print(
                f"[green]✓[/green] Namespace '{self.namespace}' already exists"
            )
        except ApiException as e:
            if e.status == 404:
                # Namespace doesn't exist, create it
                namespace_body = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=self.namespace)
                )
                self.v1.create_namespace(body=namespace_body)
                console.print(f"[green]✓[/green] Created namespace: {self.namespace}")
            else:
                raise

    def process_secret_value(self, value: Any, secret_name: str, key: str) -> str:
        """Process a secret value, handling special generation patterns."""
        if isinstance(value, str):
            if value == "{{ generate_password }}":
                generated = self.generator.generate_password()
                self.generated_values[f"{secret_name}.{key}"] = generated
                return generated
            elif value == "{{ generate_hex_key }}":
                generated = self.generator.generate_hex_key()
                self.generated_values[f"{secret_name}.{key}"] = generated
                return generated
            elif value.startswith("{{ generate_password("):
                # Extract length parameter
                length_str = value.split("(")[1].split(")")[0]
                length = int(length_str)
                generated = self.generator.generate_password(length)
                self.generated_values[f"{secret_name}.{key}"] = generated
                return generated
        return str(value)

    def check_secret_exists(self, secret_name: str) -> bool:
        """Check if a secret already exists in the namespace."""
        try:
            self.v1.read_namespaced_secret(name=secret_name, namespace=self.namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise

    def create_tls_secret(self, secret_name: str, hostname: str) -> bool:
        """Create a TLS secret with self-signed certificate."""
        try:
            cert_content, key_content = self.generator.generate_self_signed_cert(
                hostname
            )

            secret_exists = self.check_secret_exists(secret_name)
            if secret_exists:
                self.existing_secrets.append(secret_name)
                if not self.overwrite:
                    self.skipped_secrets.append(secret_name)
                    console.print(
                        f"[yellow]⚠[/yellow] Secret '{secret_name}' already exists and --overwrite is False. Skipping."
                    )
                    return True
                else:
                    self.overwritten_secrets.append(secret_name)

            if self.dry_run:
                action = "overwrite" if secret_exists and self.overwrite else "create"
                console.print(
                    f"[yellow]Would {action} TLS secret: {secret_name} for hostname: {hostname}[/yellow]"
                )
                return True

            # Delete existing secret if it exists and overwrite is enabled
            if secret_exists and self.overwrite:
                try:
                    self.v1.delete_namespaced_secret(
                        name=secret_name, namespace=self.namespace
                    )
                    console.print(
                        f"[yellow]Overwriting existing secret: {secret_name}[/yellow]"
                    )
                except ApiException as e:
                    if e.status != 404:
                        raise

            # Create TLS secret
            secret_body = client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=secret_name, namespace=self.namespace
                ),
                type="kubernetes.io/tls",
                data={
                    "tls.crt": base64.b64encode(cert_content.encode()).decode(),
                    "tls.key": base64.b64encode(key_content.encode()).decode(),
                },
            )

            self.v1.create_namespaced_secret(namespace=self.namespace, body=secret_body)
            action = "Overwritten" if secret_exists and self.overwrite else "Created"
            console.print(
                f"[green]✓[/green] {action} TLS secret: {secret_name} for hostname: {hostname}"
            )
            return True

        except Exception as e:
            console.print(
                f"[red]✗[/red] Failed to create TLS secret {secret_name}: {e}"
            )
            return False

    def create_generic_secret(self, secret_name: str, data: Dict[str, str]) -> bool:
        """Create a generic secret."""
        try:
            secret_exists = self.check_secret_exists(secret_name)
            if secret_exists:
                self.existing_secrets.append(secret_name)
                if not self.overwrite:
                    self.skipped_secrets.append(secret_name)
                    console.print(
                        f"[yellow]⚠[/yellow] Secret '{secret_name}' already exists and --overwrite is False. Skipping."
                    )
                    return True
                else:
                    self.overwritten_secrets.append(secret_name)

            if self.dry_run:
                action = "overwrite" if secret_exists and self.overwrite else "create"
                console.print(
                    f"[yellow]Would {action} generic secret: {secret_name} with keys: {list(data.keys())}[/yellow]"
                )
                return True

            # Delete existing secret if it exists and overwrite is enabled
            if secret_exists and self.overwrite:
                try:
                    self.v1.delete_namespaced_secret(
                        name=secret_name, namespace=self.namespace
                    )
                    console.print(
                        f"[yellow]Overwriting existing secret: {secret_name}[/yellow]"
                    )
                except ApiException as e:
                    if e.status != 404:
                        raise

            # Create generic secret
            secret_body = client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=secret_name, namespace=self.namespace
                ),
                type="Opaque",
                data={
                    k: base64.b64encode(v.encode()).decode() for k, v in data.items()
                },
            )

            self.v1.create_namespaced_secret(namespace=self.namespace, body=secret_body)
            action = "Overwritten" if secret_exists and self.overwrite else "Created"
            console.print(f"[green]✓[/green] {action} generic secret: {secret_name}")
            return True

        except Exception as e:
            console.print(
                f"[red]✗[/red] Failed to create generic secret {secret_name}: {e}"
            )
            return False

    def create_secrets_from_config(self, config: Dict[str, Any]) -> bool:
        """Create all secrets defined in the configuration."""
        self.ensure_namespace()

        secrets_config = config.get("secrets", [])
        success_count = 0
        total_count = len(secrets_config)

        console.print(
            f"\n[bold]Processing {total_count} secrets in namespace: {self.namespace}[/bold]"
        )
        if self.dry_run:
            console.print("[yellow]DRY RUN MODE - No changes will be made[/yellow]")

        if not self.overwrite:
            console.print(
                "[blue]ℹ Existing secrets will be skipped (use --overwrite to replace them)[/blue]"
            )
        else:
            console.print("[orange3]⚠ Existing secrets will be overwritten[/orange3]")

        for secret_config in secrets_config:
            secret_name = secret_config.get("name")
            secret_type = secret_config.get("type", "generic")

            console.print(
                f"\n[bold blue]=== Creating {secret_type} secret: {secret_name} ===[/bold blue]"
            )

            if secret_type == "tls":
                # Handle TLS secrets
                tls_data = secret_config.get("data", {})
                hostname = tls_data.get("hostname", "localhost")
                if self.create_tls_secret(secret_name, hostname):
                    success_count += 1

            elif secret_type in ["generic", "opaque"]:
                # Handle generic/opaque secrets
                data_list = secret_config.get("data", [])
                processed_data = {}

                for item in data_list:
                    key = item.get("key")
                    value = item.get("value")
                    processed_value = self.process_secret_value(value, secret_name, key)
                    processed_data[key] = processed_value

                if self.create_generic_secret(secret_name, processed_data):
                    success_count += 1
            else:
                console.print(f"[red]✗[/red] Unsupported secret type: {secret_type}")

        return success_count == total_count

    def print_summary(self, success: bool):
        """Print a summary of the operation."""
        console.print("\n" + "=" * 50)
        console.print("[bold]Summary[/bold]")
        console.print("=" * 50)

        # Report on existing secrets
        if self.existing_secrets:
            console.print(
                f"\n[yellow]⚠ Found {len(self.existing_secrets)} existing secrets:[/yellow]"
            )
            for secret in self.existing_secrets:
                console.print(f"  - {secret}")

            if self.overwritten_secrets:
                console.print(
                    f"\n[orange3]↻ Overwritten {len(self.overwritten_secrets)} secrets:[/orange3]"
                )
                for secret in self.overwritten_secrets:
                    console.print(f"  - {secret}")

            if self.skipped_secrets:
                console.print(
                    f"\n[blue]⏭ Skipped {len(self.skipped_secrets)} existing secrets (use --overwrite to replace):[/blue]"
                )
                for secret in self.skipped_secrets:
                    console.print(f"  - {secret}")

        if self.dry_run:
            console.print(
                "\n[yellow]DRY RUN completed - no secrets were actually created[/yellow]"
            )
        elif success:
            console.print(
                f"\n[green]✓ All CI secrets processed successfully in namespace: {self.namespace}[/green]"
            )
            console.print(
                "[green]✓ Secrets are ready for use with External Secrets Operator[/green]"
            )

            console.print("\nTo verify the secrets, run:")
            console.print(
                f"[cyan]kubectl get secrets -n {self.namespace} --context={self.context}[/cyan]"
            )

            if self.generated_values:
                console.print(
                    "\n[bold red]IMPORTANT: Store the generated values securely![/bold red]"
                )

                table = Table(title="Generated Secret Values")
                table.add_column("Secret.Key", style="cyan")
                table.add_column("Generated Value", style="yellow")

                for key, value in self.generated_values.items():
                    # Mask password values for display
                    display_value = (
                        value if len(value) <= 8 else value[:4] + "..." + value[-4:]
                    )
                    table.add_row(key, display_value)

                console.print(table)
        else:
            console.print("[red]✗ Some secrets failed to create[/red]")


def main(
    context: Annotated[str, typer.Option(help="Kubernetes context to use")],
    namespace: Annotated[
        str, typer.Option(help="Namespace to create secrets in (default: secret-store)")
    ] = "secret-store",
    dry_run: Annotated[
        bool, typer.Option(help="Only show what would be created, don't apply")
    ] = False,
    overwrite: Annotated[
        bool, typer.Option(help="Overwrite existing secrets (default: False)")
    ] = False,
    config: Annotated[
        str,
        typer.Option(
            help="Path to secrets configuration file (default: ci-secrets.yaml)"
        ),
    ] = "ci-secrets.yaml",
):
    """
    Create CI secrets for External Secrets Operator.

    Examples:
      uv run create-ci-secrets.py --context k3d-dev
      uv run create-ci-secrets.py --context k3d-dev --dry-run
      uv run create-ci-secrets.py --context k3d-dev --overwrite
      uv run create-ci-secrets.py --context k3d-dev --namespace my-secret-store

      # Traditional python execution (requires virtual environment)
      python create-ci-secrets.py --context k3d-dev --dry-run --overwrite
    """
    # Initialize secrets manager
    manager = CISecretsManager(
        context=context, namespace=namespace, dry_run=dry_run, overwrite=overwrite
    )

    # Load configuration and create secrets
    secrets_config = manager.load_secrets_config(config)
    success = manager.create_secrets_from_config(secrets_config)

    # Print summary
    manager.print_summary(success)

    # Exit with appropriate code
    raise typer.Exit(code=0 if success else 1)


if __name__ == "__main__":
    typer.run(main)
