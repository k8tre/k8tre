#!/usr/bin/env python3
"""Wait for K8TRE applications, gateway, and login endpoints to become ready."""

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib3
import requests

urllib3.disable_warnings()


def wait_for_root_app(timeout=300):
    print("Waiting for root-app-of-apps to be Healthy...")
    cmd = [
        "kubectl",
        "-n",
        "argocd",
        "wait",
        "--for=jsonpath={.status.health.status}=Healthy",
        "application",
        "root-app-of-apps",
        f"--timeout={timeout}s",
    ]
    subprocess.run(cmd, check=True)


def wait_for_child_apps(expected_apps=12, timeout=600):
    print("Waiting for all child applications...")
    start = time.time()
    while time.time() - start < timeout:
        res = subprocess.run(
            ["kubectl", "get", "app", "-n", "argocd", "-o", "json"],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            time.sleep(5)
            continue

        try:
            items = json.loads(res.stdout).get("items", [])
        except json.JSONDecodeError:
            time.sleep(5)
            continue

        if len(items) < expected_apps:
            print(
                f"Discovered {len(items)}/{expected_apps} applications so far... waiting."
            )
            time.sleep(10)
            continue

        all_ready = True
        elapsed = int(time.time() - start)
        print(f"\n--- App status at {elapsed}s ({len(items)} apps) ---", flush=True)
        for app in items:
            name = app.get("metadata", {}).get("name", "unknown")
            sync = app.get("status", {}).get("sync", {}).get("status", "Unknown")
            health = app.get("status", {}).get("health", {}).get("status", "Unknown")
            print(f"{name:32s} Sync: {sync:12s} Health: {health}", flush=True)
            if sync != "Synced":
                all_ready = False
                conditions = app.get("status", {}).get("conditions", [])
                if any(c.get("type") == "SyncError" for c in conditions) or health == "Healthy":
                    # Refresh to clear transient sync error or re-trigger reconciliation
                    subprocess.run(
                        [
                            "kubectl",
                            "-n",
                            "argocd",
                            "annotate",
                            "app",
                            name,
                            "argocd.argoproj.io/refresh=normal",
                            "--overwrite",
                        ],
                        capture_output=True,
                    )
            if health not in ("Healthy", "Progressing"):
                all_ready = False
            elif health != "Healthy" and name != "gateway-in-cluster":
                all_ready = False

        if all_ready:
            print("\nAll applications are Synced and Healthy!", flush=True)
            return

        time.sleep(10)

    raise TimeoutError(
        f"Timed out after {timeout}s waiting for applications to become Synced and Healthy"
    )


def wait_for_gateway_certificate(timeout=120):
    print("Waiting for Gateway TLS certificate...")
    cmd = [
        "kubectl",
        "wait",
        "--for=condition=Ready",
        "certificate/gw-tls",
        "-n",
        "gateway",
        f"--timeout={timeout}s",
    ]
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print("Warning: Gateway TLS certificate condition Ready check did not return 0; continuing.")


def wait_for_gateway_https(domain, timeout=180):
    print("Waiting for Gateway HTTPS port 443 to accept connections...")
    expected_hostname = f"keycloak.{domain}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    res = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
    node_ip = res.stdout.split()[0] if res.stdout else "127.0.0.1"

    start = time.time()
    working_host = None
    while time.time() - start < timeout:
        for candidate in ["127.0.0.1", node_ip]:
            try:
                with socket.create_connection((candidate, 443), timeout=2) as sock:
                    with ctx.wrap_socket(sock, server_hostname=expected_hostname) as ssl_sock:
                        cert = ssl_sock.getpeercert(binary_form=True)
                        if cert:
                            print(f"Gateway HTTPS responded on {candidate}!")
                            working_host = candidate
                            break
            except Exception:
                pass
        if working_host:
            break
        print(f"Waiting for Gateway HTTPS port 443 on 127.0.0.1 / {node_ip}...")
        time.sleep(3)
    else:
        raise TimeoutError(
            f"Timed out after {timeout}s waiting for Gateway HTTPS listener to accept connections on 127.0.0.1 or {node_ip}"
        )

    github_env = os.getenv("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            f.write(f"INGRESS_HOST={working_host}\n")
    print(f"Set INGRESS_HOST={working_host}")
    return working_host


def wait_for_keycloak_login(domain, timeout=180):
    print("Waiting for Keycloak login endpoint to be ready...")
    login_url = f"https://portal.{domain}/login"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(login_url, verify=False, timeout=10)
            if r.status_code == 200 and (
                "username" in r.text.lower() or "sign in" in r.text.lower()
            ):
                print("Portal login endpoint is ready and Keycloak client is active!")
                return
            print(f"Waiting for Keycloak login form (status={r.status_code})...")
        except Exception as e:
            print(f"Waiting for portal/keycloak: {e}")
        time.sleep(5)

    raise TimeoutError(
        f"Timed out after {timeout}s waiting for Portal Keycloak login to become ready"
    )


def main():
    domain = os.getenv("K8TRE_DOMAIN", "dev.k8tre.internal")
    wait_for_root_app()
    wait_for_child_apps()
    wait_for_gateway_certificate()
    wait_for_gateway_https(domain)
    wait_for_keycloak_login(domain)
    print("\n=== K8TRE deployment readiness checks completed successfully! ===")


if __name__ == "__main__":
    main()
