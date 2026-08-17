#!/usr/bin/env python3
"""Unit tests for netpol_detect, isolation_backend (v0.6.0)."""
import os
import sys
import unittest
from unittest.mock import patch, mock_open
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "src", ROOT / "scripts", ROOT / "dashboard"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from core.netpol_detect import (
    CNIMode, detect_cni, get_isolation_backend,
    _check_cni_config, _check_host_interfaces, _check_iptables_chain,
)


class TestCNIMode(unittest.TestCase):
    """CNI 探测多信号表决测试。"""

    # -----------------------------------------------------------
    # _check_cni_config
    # -----------------------------------------------------------

    @patch("os.listdir", return_value=["10-flannel.conflist"])
    @patch("os.path.isdir", return_value=True)
    def test_cni_config_flannel(self, mock_isdir, mock_listdir):
        self.assertEqual(_check_cni_config(), CNIMode.FLANNEL)

    @patch("os.listdir", return_value=["10-calico.conflist", "calico-kube-controllers.yaml"])
    @patch("os.path.isdir", return_value=True)
    def test_cni_config_calico(self, mock_isdir, mock_listdir):
        self.assertEqual(_check_cni_config(), CNIMode.CALICO)

    @patch("os.listdir", return_value=["10-cilium-conflist"])
    @patch("os.path.isdir", return_value=True)
    def test_cni_config_cilium(self, mock_isdir, mock_listdir):
        self.assertEqual(_check_cni_config(), CNIMode.CILIUM)

    @patch("os.listdir", return_value=["00-multus.conf", "10-flannel.conflist"])
    @patch("os.path.isdir", return_value=True)
    def test_cni_config_first_match(self, mock_isdir, mock_listdir):
        """sorted 后第一个匹配生效。"""
        self.assertEqual(_check_cni_config(), CNIMode.FLANNEL)

    @patch("os.path.isdir", return_value=False)
    def test_cni_config_no_dir(self, mock_isdir):
        self.assertIsNone(_check_cni_config())

    @patch("os.listdir", side_effect=PermissionError)
    @patch("os.path.isdir", return_value=True)
    def test_cni_config_permission_denied(self, mock_isdir, mock_listdir):
        self.assertIsNone(_check_cni_config())

    # -----------------------------------------------------------
    # _check_host_interfaces
    # -----------------------------------------------------------

    @patch("builtins.open", new_callable=mock_open,
           read_data="Inter-|   Receive\n face |bytes\nflannel.1:  1000\neth0:  500\n")
    def test_host_iface_flannel(self, mock_file):
        self.assertEqual(_check_host_interfaces(), CNIMode.FLANNEL)

    @patch("builtins.open", new_callable=mock_open,
           read_data="Inter-|   Receive\n face |bytes\ntunl0:  1000\neth0:  500\n")
    def test_host_iface_calico(self, mock_file):
        self.assertEqual(_check_host_interfaces(), CNIMode.CALICO)

    @patch("builtins.open", new_callable=mock_open,
           read_data="Inter-|   Receive\n face |bytes\ncilium_host:  1000\ncilium_net:  500\n")
    def test_host_iface_cilium(self, mock_file):
        self.assertEqual(_check_host_interfaces(), CNIMode.CILIUM)

    @patch("builtins.open", new_callable=mock_open,
           read_data="Inter-|   Receive\n face |bytes\neth0:  1000\nlo:  500\n")
    def test_host_iface_unknown(self, mock_file):
        self.assertIsNone(_check_host_interfaces())

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_host_iface_no_proc_net(self, mock_file):
        self.assertIsNone(_check_host_interfaces())

    # -----------------------------------------------------------
    # _check_iptables_chain
    # -----------------------------------------------------------

    @patch("subprocess.run")
    def test_iptables_kube_router(self, mock_run):
        mock_run.return_value.returncode = 0
        self.assertEqual(_check_iptables_chain(), CNIMode.KUBE_ROUTER)

    @patch("subprocess.run")
    def test_iptables_not_kube_router(self, mock_run):
        mock_run.return_value.returncode = 1
        self.assertIsNone(_check_iptables_chain())

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_iptables_no_iptables(self, mock_run):
        self.assertIsNone(_check_iptables_chain())

    # -----------------------------------------------------------
    # detect_cni() — 多信号表决
    # -----------------------------------------------------------

    @patch("core.netpol_detect._check_cni_config", return_value=CNIMode.FLANNEL)
    @patch("core.netpol_detect._check_host_interfaces", return_value=CNIMode.FLANNEL)
    @patch("core.netpol_detect._check_iptables_chain", return_value=None)
    def test_detect_flannel(self, mock_ipt, mock_iface, mock_conf):
        self.assertEqual(detect_cni(), CNIMode.FLANNEL)

    @patch("core.netpol_detect._check_cni_config", return_value=CNIMode.CALICO)
    @patch("core.netpol_detect._check_host_interfaces", return_value=CNIMode.CALICO)
    @patch("core.netpol_detect._check_iptables_chain", return_value=None)
    def test_detect_calico(self, mock_ipt, mock_iface, mock_conf):
        self.assertEqual(detect_cni(), CNIMode.CALICO)

    @patch("core.netpol_detect._check_cni_config", return_value=CNIMode.CILIUM)
    @patch("core.netpol_detect._check_host_interfaces", return_value=CNIMode.CILIUM)
    @patch("core.netpol_detect._check_iptables_chain", return_value=None)
    def test_detect_cilium(self, mock_ipt, mock_iface, mock_conf):
        self.assertEqual(detect_cni(), CNIMode.CILIUM)

    @patch("core.netpol_detect._check_cni_config", return_value=None)
    @patch("core.netpol_detect._check_host_interfaces", return_value=None)
    @patch("core.netpol_detect._check_iptables_chain", return_value=CNIMode.KUBE_ROUTER)
    def test_detect_kube_router_iptables_signal(self, mock_ipt, mock_iface, mock_conf):
        """iptables chain signal has highest confidence."""
        self.assertEqual(detect_cni(), CNIMode.KUBE_ROUTER)

    @patch("core.netpol_detect._check_cni_config", return_value=None)
    @patch("core.netpol_detect._check_host_interfaces", return_value=None)
    @patch("core.netpol_detect._check_iptables_chain", return_value=None)
    def test_detect_unknown(self, mock_ipt, mock_iface, mock_conf):
        self.assertEqual(detect_cni(), CNIMode.UNKNOWN)

    @patch("core.netpol_detect._check_cni_config", return_value=CNIMode.FLANNEL)
    @patch("core.netpol_detect._check_host_interfaces", return_value=CNIMode.CALICO)
    @patch("core.netpol_detect._check_iptables_chain", return_value=None)
    def test_detect_conflict_fallback_to_iface(self, mock_ipt, mock_iface, mock_conf):
        """Config/iface conflict -> iface preferred (lower confidence)."""
        self.assertEqual(detect_cni(), CNIMode.CALICO)

    # -----------------------------------------------------------
    # get_isolation_backend
    # -----------------------------------------------------------

    @patch("responder.isolation_backend.NsenterIptablesBackend")
    def test_backend_flannel_iptables(self, mock_backend):
        backend = get_isolation_backend(CNIMode.FLANNEL)
        self.assertIsNotNone(backend)

    @patch("responder.isolation_backend.NsenterIptablesBackend")
    def test_backend_unknown_iptables(self, mock_backend):
        backend = get_isolation_backend(CNIMode.UNKNOWN)
        self.assertIsNotNone(backend)

    @patch("responder.k8s_network_policy.NetworkPolicyBackend")
    def test_backend_calico_netpol(self, mock_backend):
        backend = get_isolation_backend(CNIMode.CALICO)
        self.assertIsNotNone(backend)

    @patch("responder.k8s_network_policy.NetworkPolicyBackend")
    def test_backend_cilium_netpol(self, mock_backend):
        backend = get_isolation_backend(CNIMode.CILIUM)
        self.assertIsNotNone(backend)

    @patch("responder.k8s_network_policy.NetworkPolicyBackend")
    def test_backend_kube_router_netpol(self, mock_backend):
        backend = get_isolation_backend(CNIMode.KUBE_ROUTER)
        self.assertIsNotNone(backend)


if __name__ == "__main__":
    unittest.main()