from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import os
import requests
import ssl
import socket
import pytest

INGRESS_HOST = os.getenv("INGRESS_HOST", "localhost")
K8TRE_DOMAIN = os.getenv("K8TRE_DOMAIN", "dev.k8tre.internal")


def test_web_ingress_keycloak():
    """
    Check that Keycloak is accessible via ingress
    """

    KEYCLOAK_HOST = f"keycloak.{K8TRE_DOMAIN}"
    # Keycloak / should redirect to KEYCLOAK_HOST/admin/
    r = requests.get(
        f"https://{INGRESS_HOST}/",
        headers={"Host": KEYCLOAK_HOST},
        verify=False,
        allow_redirects=False,
    )

    assert r.status_code == 302
    assert r.headers["Location"] == f"https://{KEYCLOAK_HOST}/admin/"

    # Which should redirect to KEYCLOAK_HOST/admin/master/console/
    r = requests.get(
        f"https://{INGRESS_HOST}/admin/",
        headers={"Host": KEYCLOAK_HOST},
        verify=False,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == f"https://{KEYCLOAK_HOST}/admin/master/console/"


def test_web_ingress_jupyterhub():
    """
    Check that JupyterHub is accessible via ingress
    """

    JUPYTERHUB_HOST = f"jupyter.{K8TRE_DOMAIN}"
    # JupyterHub / should redirect to /hub/
    r = requests.get(
        f"https://{INGRESS_HOST}/",
        headers={"Host": JUPYTERHUB_HOST},
        verify=False,
        allow_redirects=False,
    )

    assert r.status_code == 302
    assert r.headers["Location"] == "/hub/"

    # Which should redirect to /hub/home (JupyterHub.default_url)
    r = requests.get(
        f"https://{INGRESS_HOST}/hub/",
        headers={"Host": JUPYTERHUB_HOST},
        verify=False,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "/hub/home"

    # Which should redirect to /hub/login?next=%2Fhub%2F
    r = requests.get(
        f"https://{INGRESS_HOST}/hub/home",
        headers={"Host": JUPYTERHUB_HOST},
        verify=False,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/hub/login")


@pytest.mark.parametrize("subdomain", ["guacamole", "jupyter", "keycloak"])
def test_ingress_certificates(subdomain):
    """
    Checking an ingress subdomain has the expected certificate
    """
    expected_hostname = f"{subdomain}.{K8TRE_DOMAIN}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Create a standard TCP socket, then wrap it with TLS and SNI
    with socket.create_connection((INGRESS_HOST, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=expected_hostname) as ssl_sock:
            # Extract domain name from the certificate
            peer_cert_der = ssl_sock.getpeercert(binary_form=True)
            assert peer_cert_der, "Server did not present a certificate"

            cert = x509.load_der_x509_certificate(peer_cert_der, default_backend())

            cn = None
            for attribute in cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    cn = attribute.value
                    break

            san_names = []
            try:
                san_extension = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )
                for general_name in san_extension.value:
                    if isinstance(general_name, x509.DNSName):
                        san_names.append(general_name.value)
            except x509.ExtensionNotFound:
                pass

            print(f"CN: {cn}")
            print(f"SAN: {san_names}")

            # Check the domain name
            assert (cn and cn.lower() == expected_hostname.lower()) or (
                expected_hostname.lower() in [name.lower() for name in san_names]
            ), f"Domain name '{expected_hostname}' not in certificate."
