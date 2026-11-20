from mininet.topo import Topo


class RedundantTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        # Link creation order determines OpenFlow port numbers in Mininet.
        # Keep these mappings consistent with experiments/topologies.py:
        #   h1 -- s1-p1
        #   trunk A: s1-p2 <-> s2-p1
        #   trunk B: s1-p3 <-> s2-p2
        #   h2 -- s2-p3
        self.addLink(h1, s1)
        self.addLink(s1, s2)   # trunk A
        self.addLink(s1, s2)   # trunk B (redundant)
        self.addLink(h2, s2)

topos = {'redundant': (lambda: RedundantTopo())}
