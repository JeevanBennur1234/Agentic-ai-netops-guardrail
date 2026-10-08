from mininet.topo import Topo

class RedundantTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(h1, s1)   # h1 -> s1-p1
        self.addLink(h2, s2)   # h2 -> s2-p3
        self.addLink(s1, s2)   # trunk 1: s1-p2 <-> s2-p1
        self.addLink(s1, s2)   # trunk 2 (redundant): s1-p3 <-> s2-p2

topos = {'redundant': (lambda: RedundantTopo())}
