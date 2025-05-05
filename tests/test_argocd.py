import kubernetes
import json
import os
import pytest

kubernetes.config.load_config()


def get_applications():
    crd_api = kubernetes.client.CustomObjectsApi()
    apps = crd_api.list_cluster_custom_object("argoproj.io", "v1alpha1", "applications")
    return apps["items"]


def application_id_fn(app):
    return f"{app['metadata']['namespace']}/{app['metadata']['name']}"


@pytest.mark.parametrize("app", get_applications(), ids=application_id_fn)
def test_argocd_application_repos(app):
    """
    Check that repoURL and targetRevision has been changed so that we've
    deployed the fork/branch when testing in CI

    If running in GitHub CI then either repoURL is not k8tre, or repoURL and
    targetRevision match GITHUB_REPOSITORY and GITHUB_SHA
    """
    repo = os.getenv("GITHUB_REPOSITORY")
    sha = os.getenv("GITHUB_SHA")

    # https://argo-cd.readthedocs.io/en/latest/user-guide/application-specification/
    sources = []
    s = app["spec"].get("source")
    if s:
        sources.append(s)
    sources.extend(app["spec"].get("sources", []))

    for s in sources:
        print(json.dumps(s, indent=2))
        if s and "k8tre" in s["repoURL"]:
            assert s["repoURL"].removesuffix(".git") == f"https://github.com/{repo}"
            assert s["targetRevision"] == sha
