#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#   "kubernetes>=29.0.0",
#   "typer>=0.16.0",
#   "pyyaml>=6.0.0",
# ]
# ///
"""
CI Secrets Management for External Secrets Operator

This script creates Kubernetes secrets in a secret-store namespace for use with
External Secrets Operator in CI environments. It reads configuration from
secrets.yaml and generates necessary passwords and keys automatically.

The script supports three modes:
- Create new secrets (default): Only creates secrets that don't exist
- Overwrite mode (--overwrite): Completely replaces existing secrets
- Merge mode (--merge-keys): Adds new keys to existing secrets without overwriting existing keys

Note: TLS secrets are now managed by cert-manager and are not created by this script.

Usage:
    uv run create-ci-secrets.py --context k3d-dev [--dry-run] [--namespace secret-store]
    uv run create-ci-secrets.py --context k3d-dev --merge-keys [--dry-run]

"""

import base64
import secrets
import string
import sys
from pathlib import Path
from typing import Annotated, Any, Dict

import typer
import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from rich.console import Console
from rich.table import Table

console = Console()


class SecretGenerator:
    """Generates various types of secrets like passwords and hex keys."""

    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate a random password."""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_hex_key(length: int = 32) -> str:
        """Generate a random hex key."""
        return secrets.token_hex(length)


class CISecretsManager:
    """Manages creation of CI secrets for External Secrets Operator."""

    def __init__(
        self,
        context: str,
        namespace: str = "secret-store",
        dry_run: bool = False,
        overwrite: bool = False,
        merge_keys: bool = False,
    ):
        self.context = context
        self.namespace = namespace
        self.dry_run = dry_run
        self.overwrite = overwrite
        self.merge_keys = merge_keys
        self.generator = SecretGenerator()
        self.generated_values = {}
        self.existing_secrets = []
        self.overwritten_secrets = []
        self.skipped_secrets = []
        self.merged_secrets = []

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

    def get_existing_secret_data(self, secret_name: str) -> Dict[str, str]:
        """Get the data from an existing secret."""
        try:
            secret = self.v1.read_namespaced_secret(name=secret_name, namespace=self.namespace)
            if secret.data:
                # Decode base64 values
                return {k: base64.b64decode(v).decode() for k, v in secret.data.items()}
            return {}
        except ApiException as e:
            if e.status == 404:
                return {}
            raise

    def create_generic_secret(self, secret_name: str, data: Dict[str, str]) -> bool:
        """Create a generic secret."""
        try:
            secret_exists = self.check_secret_exists(secret_name)
            final_data = data.copy()
            
            if secret_exists:
                self.existing_secrets.append(secret_name)
                
                if self.merge_keys:
                    # Merge with existing secret data
                    existing_data = self.get_existing_secret_data(secret_name)
                    # Start with existing data, then add/override with new data
                    final_data = existing_data.copy()
                    final_data.update(data)
                    self.merged_secrets.append(secret_name)
                    
                    if self.dry_run:
                        console.print(
                            f"[yellow]Would merge keys into existing secret: {secret_name}[/yellow]"
                        )
                        console.print(f"[yellow]  Existing keys: {list(existing_data.keys())}[/yellow]")
                        console.print(f"[yellow]  New/Updated keys: {list(data.keys())}[/yellow]")
                        console.print(f"[yellow]  Final keys: {list(final_data.keys())}[/yellow]")
                        return True
                elif not self.overwrite:
                    self.skipped_secrets.append(secret_name)
                    console.print(
                        f"[yellow]⚠[/yellow] Secret '{secret_name}' already exists. Use --overwrite to replace or --merge-keys to add new keys."
                    )
                    return True
                else:
                    self.overwritten_secrets.append(secret_name)

            if self.dry_run and not (secret_exists and self.merge_keys):
                action = "overwrite" if secret_exists and self.overwrite else "create"
                console.print(
                    f"[yellow]Would {action} generic secret: {secret_name} with keys: {list(final_data.keys())}[/yellow]"
                )
                return True

            # Delete existing secret if it exists and we're overwriting (not merging)
            if secret_exists and self.overwrite and not self.merge_keys:
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
            elif secret_exists and self.merge_keys:
                # Delete existing secret to recreate with merged data
                try:
                    self.v1.delete_namespaced_secret(
                        name=secret_name, namespace=self.namespace
                    )
                    console.print(
                        f"[cyan]Merging keys into existing secret: {secret_name}[/cyan]"
                    )
                except ApiException as e:
                    if e.status != 404:
                        raise

            # Create generic secret with final data
            secret_body = client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=secret_name, namespace=self.namespace
                ),
                type="Opaque",
                data={
                    k: base64.b64encode(v.encode()).decode() for k, v in final_data.items()
                },
            )

            self.v1.create_namespaced_secret(namespace=self.namespace, body=secret_body)
            
            if secret_exists and self.merge_keys:
                console.print(f"[green]✓[/green] Merged keys into secret: {secret_name}")
            elif secret_exists and self.overwrite:
                console.print(f"[green]✓[/green] Overwritten secret: {secret_name}")
            else:
                console.print(f"[green]✓[/green] Created generic secret: {secret_name}")
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

        if not self.overwrite and not self.merge_keys:
            console.print(
                "[blue]ℹ Existing secrets will be skipped (use --overwrite to replace them or --merge-keys to add new keys)[/blue]"
            )
        elif self.overwrite and not self.merge_keys:
            console.print("[orange3]⚠ Existing secrets will be overwritten[/orange3]")
        elif self.merge_keys:
            console.print("[cyan]🔀 New keys will be merged into existing secrets[/cyan]")

        for secret_config in secrets_config:
            secret_name = secret_config.get("name")
            secret_type = secret_config.get("type", "generic")

            console.print(
                f"\n[bold blue]=== Creating {secret_type} secret: {secret_name} ===[/bold blue]"
            )

            if secret_type in ["generic", "opaque"]:
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
            elif secret_type == "tls":
                # TLS secrets are now managed by cert-manager, skipping
                console.print(
                    f"[yellow]⚠[/yellow] TLS secret '{secret_name}' is managed by cert-manager, skipping creation."
                )
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

            if self.merged_secrets:
                console.print(
                    f"\n[cyan]🔀 Merged keys into {len(self.merged_secrets)} existing secrets:[/cyan]"
                )
                for secret in self.merged_secrets:
                    console.print(f"  - {secret}")

            if self.skipped_secrets:
                console.print(
                    f"\n[blue]⏭ Skipped {len(self.skipped_secrets)} existing secrets (use --overwrite to replace or --merge-keys to add new keys):[/blue]"
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
    merge_keys: Annotated[
        bool, typer.Option(help="Merge new keys into existing secrets without overwriting existing keys (default: False)")
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
      uv run create-ci-secrets.py --context k3d-dev --merge-keys
      uv run create-ci-secrets.py --context k3d-dev --namespace my-secret-store

      # Traditional python execution (requires virtual environment)
      python create-ci-secrets.py --context k3d-dev --dry-run --merge-keys
    """
    
    # Validate conflicting options
    if overwrite and merge_keys:
        console.print("[red]Error: --overwrite and --merge-keys options are mutually exclusive.[/red]")
        console.print("[yellow]Use --overwrite to completely replace existing secrets, or --merge-keys to add new keys to existing secrets.[/yellow]")
        raise typer.Exit(code=1)
    
    # Initialize secrets manager
    manager = CISecretsManager(
        context=context, namespace=namespace, dry_run=dry_run, overwrite=overwrite, merge_keys=merge_keys
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
