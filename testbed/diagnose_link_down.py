#!/usr/bin/env python3
"""Diagnostic for whether Mininet link-down causes OVS OpenFlow port-status updates."""
import os, socket, subprocess, sys, time
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo

class TriangleTopo(Topo):
    def build(self):
        s1=self.addSwitch("s1"); s2=self.addSwitch("s2"); s3=self.addSwitch("s3")
        h1=self.addHost("h1"); h2=self.addHost("h2")
        self.addLink(h1,s1); self.addLink(s1,s2); self.addLink(s2,s3)
        self.addLink(s3,s1); self.addLink(h2,s3)

def run(args):
    return subprocess.run(args,capture_output=True,text=True,check=False)

def show(label):
    print("\n== "+label+" ==", flush=True)
    for bridge in ("s1","s2"):
        r=run(["ovs-ofctl","-O","OpenFlow13","dump-ports-desc",bridge])
        print(bridge, r.stdout, r.stderr, flush=True)

def main():
    if os.geteuid()!=0: return 2
    try:
        with socket.create_connection(("127.0.0.1",6653),timeout=1): pass
    except OSError as exc:
        print("Ryu unavailable:",exc); return 2
    if any(run(["ovs-vsctl","br-exists",b]).returncode==0 for b in ("s1","s2","s3")):
        print("Pre-existing bridges; refusing"); return 2
    setLogLevel("warning")
    net=Mininet(topo=TriangleTopo(),controller=None,switch=OVSKernelSwitch,
                autoSetMacs=True,build=True,waitConnected=True)
    net.addController("c0",controller=RemoteController,ip="127.0.0.1",port=6653)
    started=False
    try:
        net.start(); started=True; time.sleep(14)
        print("BASELINE LOSS",net.pingAll(timeout=1),flush=True)
        show("BEFORE")
        print("Before intf output:",net.get("s1").cmd("ip -details link show s1-eth2"),flush=True)
        print("Calling configLinkStatus(s1,s2,down)",flush=True)
        net.configLinkStatus("s1","s2","down")
        print("After intf output:",net.get("s1").cmd("ip -details link show s1-eth2"),flush=True)
        print("After peer output:",net.get("s2").cmd("ip -details link show s2-eth1"),flush=True)
        time.sleep(2); show("AFTER 2 SECONDS")
        print("POST-FAILURE LOSS",net.pingAll(timeout=1),flush=True)
        print("RESTORING LINK",flush=True)
        net.configLinkStatus("s1","s2","up")
        time.sleep(8)
        print("RESTORED LOSS",net.pingAll(timeout=1),flush=True)
        show("AFTER RESTORE")
        return 0
    finally:
        if started: net.stop()

if __name__=="__main__": raise SystemExit(main())
