import os
import requests


INGRESS_HOST = os.getenv("INGRESS_HOST", "localhost")
KEYCLOAK_HOST = os.getenv("KEYCLOAK_HOST", "keycloak.dev.k8tre.internal")
JUPYTERHUB_HOST = os.getenv("JUPYTERHUB_HOST", "jupyter.dev.k8tre.internal")


def test_web_ingress_keycloak():
    """
    Check that Keycloak is accessible via ingress
    """

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

    # JupyterHub / should redirect to /hub/
    r = requests.get(
        f"https://{INGRESS_HOST}/",
        headers={"Host": JUPYTERHUB_HOST},
        verify=False,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "/hub/"

    # Which should redirect to /hub/login?next=%2Fhub%2F
    r = requests.get(
        f"https://{INGRESS_HOST}/hub/",
        headers={"Host": JUPYTERHUB_HOST},
        verify=False,
        allow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/hub/login")
