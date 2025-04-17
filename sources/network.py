"""This module defines the topology used in testing the SDN controller. It replicates the official
SDN testbed topology described in the course slides.

This script must not be run directly but insted started directly from Mininet. For example:
mn --custom network.py --topo SDNTestbed
"""

# This import works only if the script is run directly from Mininet class loader.
# pylint: disable=import-error
from mininet.topo import Topo  # type: ignore


class SDNTestbed(Topo):
    """Topology replicating the official SDN testbed."""

    def build(self):
        """Construct the actual topology."""

        # Create the hosts
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")

        # Create the switches
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")

        # Create the links between hosts and switches
        self.addLink(h1, s1)
        self.addLink(h2, s4)
        self.addLink(h3, s5)

        # Create the links between switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)
        self.addLink(s6, s1)


# The presence of this lambda is required as per Mininet's documentation.
# pylint: disable=unnecessary-lambda
topos = {"SDNTestbed": (lambda: SDNTestbed())}
