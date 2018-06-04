"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        firstSwitch = self.addSwitch( 's1' )
        secondSwitch = self.addSwitch( 's2' )
        thirdSwitch = self.addSwitch( 's3' )
        fourthSwitch = self.addSwitch( 's4' )
        fifthSwitch = self.addSwitch( 's5' )
        sixthSwitch = self.addSwitch( 's6' )
        # Add links
        self.addLink( leftHost, firstSwitch )
        self.addLink( firstSwitch, secondSwitch )
        self.addLink(secondSwitch, thirdSwitch )
        self.addLink(thirdSwitch, fourthSwitch )
        self.addLink(fourthSwitch, fifthSwitch )
        self.addLink(fifthSwitch, sixthSwitch )
        self.addLink( sixthSwitch, rightHost )


topos = { 'mytopo': ( lambda: MyTopo() ) }
