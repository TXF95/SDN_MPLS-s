from mininet.topo import Topo
from mininet.link import Link, TCLink, Intf
#from mininet.cli import CLI
#from mininet.log import setLogLevel, info,error
#from mininet.net import Mininet
#from mininet.link import Link, TCLink, Intf
#from mininet.topolib import TreeTopo
#from mininet.util import quietRun
#from mininet.node import RemoteController, OVSKernelSwitch

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        #s8 = self.addSwitch('s8')

        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s7)
        self.addLink(h3, s5)
        self.addLink(h4, s6)

        self.addLink(s1, s2, cls=TCLink)
        self.addLink(s1, s5, cls=TCLink)
        self.addLink(s2, s3, cls=TCLink)
        self.addLink(s3, s4, cls=TCLink)
        self.addLink(s4, s7, cls=TCLink)
        self.addLink(s5, s6, cls=TCLink)
        self.addLink(s6, s7, cls=TCLink)

 
topos = { 'mytopo': ( lambda: MyTopo() ) }



