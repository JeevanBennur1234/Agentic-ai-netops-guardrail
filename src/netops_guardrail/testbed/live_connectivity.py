"""Live host-to-host checker for the local Mininet redundant topology.

Configure NETOPS_CONNECTIVITY_CHECKER=live_connectivity:check_host_connectivity.
True is returned only if both Mininet hosts are found and can ping each other.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def _host_shell_pid(host_name: str) -> int:
    marker = f"mininet:{host_name}".encode()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        if marker in cmdline:
            return int(entry.name)
    raise RuntimeError(f"Mininet shell for {host_name} not found; is the lab running?")


def _run_in_host_namespace(pid: int, command: list[str], timeout: float = 4.0):
    return subprocess.run(
        ["sudo", "-n", "mnexec", "-a", str(pid), *command],
        capture_output=True, text=True, check=False, timeout=timeout,
    )


def _host_ip(pid: int) -> str:
    result = _run_in_host_namespace(pid, ["ip", "-o", "-4", "addr", "show"])
    if result.returncode != 0:
        raise RuntimeError(f"Cannot read Mininet host IP: {result.stderr.strip()}")
    for match in re.finditer(r"\binet\s+(\d+(?:\.\d+){3})/\d+", result.stdout):
        address = match.group(1)
        if not address.startswith("127."):
            return address
    raise RuntimeError("Mininet host has no non-loopback IPv4 address")


def _can_ping(source_pid: int, destination_ip: str) -> bool:
    result = _run_in_host_namespace(
        source_pid, ["ping", "-n", "-c", "1", "-W", "2", destination_ip], timeout=4.0
    )
    return result.returncode == 0


def check_host_connectivity() -> bool:
    """Return true only if h1->h2 and h2->h1 ping checks both succeed."""
    try:
        h1_pid = _host_shell_pid("h1")
        h2_pid = _host_shell_pid("h2")
        h1_ip = _host_ip(h1_pid)
        h2_ip = _host_ip(h2_pid)
        if h1_ip == h2_ip:
            return False
        return _can_ping(h1_pid, h2_ip) and _can_ping(h2_pid, h1_ip)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


if __name__ == "__main__":
    print("connectivity_ok=" + str(check_host_connectivity()).lower())
