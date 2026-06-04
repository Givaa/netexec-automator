"""Nmap port-discovery wrapper used by --nmap / --scan-only."""

import subprocess
import xml.etree.ElementTree as ET

from .constants import NMAP_TIMEOUT


class NmapScanner:
    """Run nmap port discovery and parse XML output."""

    def __init__(self, ports: list[int], timeout: int = NMAP_TIMEOUT, log_cmd=None):
        self.ports = ports
        self.timeout = timeout
        # Optional callback: (label, cmd, target) → None. Called before each scan.
        self.log_cmd = log_cmd

    @staticmethod
    def is_available() -> bool:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, targets) -> dict[str, dict[int, str]]:
        """Run nmap on one or more targets (single host, hostname, CIDR, or an
        iterable of any of those — e.g. the subset of a range we haven't cached).
        Returns {ip_or_hostname: {port: state}} only for hosts with at least one open port."""
        target_list = [targets] if isinstance(targets, str) else list(targets)
        if not target_list:
            return {}
        port_arg = ",".join(str(p) for p in self.ports)
        cmd = ["nmap", "-Pn", "-n", "--open", "-p", port_arg, "-T4", "-oX", "-", *target_list]
        if self.log_cmd:
            label = target_list[0] if len(target_list) == 1 else f"{len(target_list)} hosts"
            self.log_cmd("nmap", cmd, label)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {}
        if result.returncode != 0 or not result.stdout:
            return {}
        return self._parse_xml(result.stdout)

    @staticmethod
    def _parse_xml(xml_str: str) -> dict[str, dict[int, str]]:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return {}

        results: dict[str, dict[int, str]] = {}
        for host in root.findall("host"):
            addr_elem = host.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host.find("address")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr")
            if not ip:
                continue
            ports_dict: dict[int, str] = {}
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    portid = port.get("portid")
                    state_elem = port.find("state")
                    if portid and state_elem is not None:
                        ports_dict[int(portid)] = state_elem.get("state", "unknown")
            results[ip] = ports_dict
        return results
