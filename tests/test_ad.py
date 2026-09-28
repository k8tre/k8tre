"""Tests for Active Directory (Samba AD DC) deployment."""

import kubernetes.client
import kubernetes.config

kubernetes.config.load_config()


def test_ad_administrator_keytab_configmap():
    """Check that administrator.keytab ConfigMap was created by samba-start."""
    core_v1 = kubernetes.client.CoreV1Api()
    cm = core_v1.read_namespaced_config_map("administrator.keytab", "ad")
    has_keytab = False
    if cm.binary_data and "Administrator.keytab" in cm.binary_data:
        has_keytab = True
    elif cm.data and "Administrator.keytab" in cm.data:
        has_keytab = True
    assert has_keytab, "Administrator.keytab not found in configmap data or binary_data"
