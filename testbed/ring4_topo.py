"""4-switch / 4-host ring topology with redundant paths.

Switches s1..s4, hosts h1..h4, OpenFlow 1.3.
Link and port assignment:
  s1: p1-h1, p2-h2, p3-s2, p4-s3
  s2: p1-s1, p2-s4
  s3: p1-s1, p2-s4
  s4: p1-h3, p2-h4, p3-s2, p4-s3
"""
from __future__ import annotations

import os
import sys

_curr_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
_proj_root = _curr_dir if os.path.exists(os.path.join(_curr_dir, "src")) else os.path.abspath(os.path.join(_curr_dir, ".."))
_src_dir = os.path.join(_proj_root, "src")
for _p in (_curr_dir, _proj_root, _src_dir):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mininet.topo import Topo
try:
    from netops_guardrail.testbed.redundant_topo import RedundantTopo
except ImportError:
    try:
        from testbed.redundant_topo import RedundantTopo
    except ImportError:
        from redundant_topo import RedundantTopo


class Ring4Topo(Topo):
    """4-switch ring topology with redundant inter-switch links and dual-host edges."""

    def build(self, **_opts):
        # Add 4 switches with OpenFlow 1.3
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")
        s4 = self.addSwitch("s4", protocols="OpenFlow13")

        # Add 4 hosts with standard IP assignment
        h1 = self.addHost("h1", ip="10.0.0.1/24")
        h2 = self.addHost("h2", ip="10.0.0.2/24")
        h3 = self.addHost("h3", ip="10.0.0.3/24")
        h4 = self.addHost("h4", ip="10.0.0.4/24")

        # Links are added in the exact order required so port numbers match:
        # s1: p1-h1, p2-h2, p3-s2, p4-s3
        # s2: p1-s1, p2-s4
        # s3: p1-s1, p2-s4
        # s4: p1-h3, p2-h4, p3-s2, p4-s3

        # 1. s1-p1 <-> h1
        self.addLink(s1, h1, port1=1, port2=1)
        # 2. s1-p2 <-> h2
        self.addLink(s1, h2, port1=2, port2=1)
        # 3. s4-p1 <-> h3
        self.addLink(s4, h3, port1=1, port2=1)
        # 4. s4-p2 <-> h4
        self.addLink(s4, h4, port1=2, port2=1)

        # 5. s1-p3 <-> s2-p1
        self.addLink(s1, s2, port1=3, port2=1)
        # 6. s1-p4 <-> s3-p1
        self.addLink(s1, s3, port1=4, port2=1)

        # 7. s2-p2 <-> s4-p3
        self.addLink(s2, s4, port1=2, port2=3)
        # 8. s3-p2 <-> s4-p4
        self.addLink(s3, s4, port1=2, port2=4)


def get_topology(name: str = "redundant2"):
    """Factory to select topology: redundant2/redundant (default) or ring4."""
    name = (name or "redundant2").strip().lower()
    if name in ("ring4", "ring", "4switch"):
        return Ring4Topo()
    return RedundantTopo()


topos = {
    "ring4": (lambda: Ring4Topo()),
    "ring": (lambda: Ring4Topo()),
    "redundant": (lambda: RedundantTopo()),
    "redundant2": (lambda: RedundantTopo()),
}

if __name__ == "__main__":
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel

    setLogLevel("info")
    topo_name = os.environ.get("NETOPS_TOPOLOGY", "ring4")
    topo = get_topology(topo_name)
    net = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        autoSetMacs=True,
    )
    net.start()
    CLI(net)
    net.stop()