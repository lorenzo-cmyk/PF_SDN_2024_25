"""Baby Elephant Walk - Ryu SDN Application"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp
import networkx as nx


class MessageFactory:
    """Class used to generate FlowMod messages to be sent to the switches."""

    def __init__(self, app):
        """Initializes the MessageFactory with the Ryu application instance."""
        self.app = app

    def default_configuration(self, switch):
        """
        Generates a FlowMod message to configure the switch to send all packets to the controller.
        :param switch: The switch to be configured.
        :return: The FlowMod message to be sent to the switch.
        """
        # Retrieve the OpenFlow protocol object and relative parser from the switch.
        ofprotocol = switch.ofproto
        ofparser = switch.ofproto_parser

        # Default configuration for the switch: sends everything to the controller.
        # Instructions: for each packet, apply the action: send everything to the controller using
        # the OFPP_CONTROLLER port.
        instructions = [
            ofparser.OFPInstructionActions(
                ofprotocol.OFPIT_APPLY_ACTIONS,
                [
                    ofparser.OFPActionOutput(
                        ofprotocol.OFPP_CONTROLLER, ofprotocol.OFPCML_NO_BUFFER
                    )
                ],
            )
        ]
        # Rule: match everything and apply the instructions. Keep the priority low to avoid
        # conflicts with other rules.
        rule = ofparser.OFPFlowMod(
            datapath=switch,
            priority=0,
            # Match: match everything (wildcard).
            match=ofparser.OFPMatch(),
            instructions=instructions,
        )

        return rule

    def arp_proxy(self, arp_req):
        """
        Generates a FlowMod message to reply to an ARP request with the MAC address of the host
        that has the IP address specified in the ARP request.
        :param app: The Ryu application instance.
        :param arp_req: The ARP request packet received by the controller.
        :return: The FlowMod message to be sent to the switch.
        """
        # Retrieve the OpenFlow protocol object and relative parser from the switch.
        # The switch itself is extracted from the ARP request.
        switch = arp_req.datapath
        ofprotocol = switch.ofproto
        ofparser = switch.ofproto_parser

        # Parse the ARP request: starts from the raw byte stream received by the controller and
        # extracts Ethernet and ARP informations.
        raw_in = packet.Packet(arp_req.data)
        eth_in = raw_in.get_protocol(ethernet.ethernet)
        arp_in = raw_in.get_protocol(arp.arp)

        # Handle only ARP requests, ignore all other types of ARP packets.
        if arp_in.opcode != arp.ARP_REQUEST:
            return

        # Finds the MAC address of the host that has the IP address specified in the ARP request.
        # If the host is not found, the function returns without doing anything.
        target_mac_address = next(
            (host.mac for host in get_all_host(self.app) if arp_in.dst_ip in host.ipv4),
            None,
        )
        if target_mac_address is None:
            return None

        # Starts building the ARP reply packet.
        raw_out = packet.Packet()
        # External Ethernet header: the destination MAC address is the source MAC address of the
        # ARP request, the source MAC address is the MAC address of the host that has the IP
        # address specified in the ARP request.
        eth_out = ethernet.ethernet(
            dst=eth_in.src,
            src=target_mac_address,
            # Ethernet type: ARP
            ethertype=ether_types.ETH_TYPE_ARP,
        )
        # ARP header: the opcode is ARP_REPLY, the source MAC address is the MAC address of the
        # host that has the IP address specified in the ARP request, the source IP address is the
        # IP address specified in the ARP request, the destination MAC address is the source MAC
        # address of the ARP request, and the destination IP address is the IP address specified in
        # the ARP request.
        arp_out = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target_mac_address,
            src_ip=arp_in.dst_ip,
            dst_mac=arp_in.src_mac,
            dst_ip=arp_in.src_ip,
        )
        raw_out.add_protocol(eth_out)
        raw_out.add_protocol(arp_out)
        raw_out.serialize()

        # Build the FlowMod message to inscruct the switch to send the ARP reply that we have just
        # built.
        arp_reply = ofparser.OFPPacketOut(
            datapath=switch,
            buffer_id=ofprotocol.OFP_NO_BUFFER,
            in_port=ofprotocol.OFPP_CONTROLLER,
            # The ARP reply is sent to the port from which the ARP request was received.
            actions=[ofparser.OFPActionOutput(arp_req.match["in_port"])],
            data=raw_out.data,
        )

        return arp_reply

    def forward_packet(self, switch, out_port, pkt):
        """
        Generates a FlowMod message to forward the packet to the specified output port.
        :param switch: The switch to which the FlowMod message will be sent.
        :param out_port: The output port to which the packet will be forwarded.
        :param pkt: The packet to be forwarded.
        :return: The FlowMod message to be sent to the switch.
        """
        # Retrive the OpenFlow parser object from the switch.
        ofparser = switch.ofproto_parser

        # Build the FlowMod message to instruct the switch to forward the packet to the specified
        # output port.
        # Actions: just forward the packet to said port.
        actions = [ofparser.OFPActionOutput(out_port)]
        # PacketOut: pack everything in a PacketOut message to be sent to the switch.
        pkt_out = ofparser.OFPPacketOut(
            datapath=switch,
            buffer_id=pkt.buffer_id,
            # Spoof the port to make it look like the packet is coming from the switch.
            # This is needed because the packet is coming from the controller and not from the
            # switch.
            in_port=pkt.match["in_port"],
            actions=actions,
            data=pkt.data,
        )

        return pkt_out


class NetworkTopology:
    """Class used to represent the network topology."""

    def __init__(self, app):
        """Initializes the NetworkTopology with the Ryu application instance."""
        self.app = app

    def __find_switch_by_host_mac(self, dst_mac):
        """
        Finds the switch that has the host with the specified MAC address connected to it.
        :param dst_mac: The MAC address of the host to be found.
        :return: The switch ID that has the host connected to it and the port number of the host.
        """
        found_host = next(
            (host for host in get_all_host(self.app) if host.mac == dst_mac), None
        )
        return (
            (found_host.port.dpid, found_host.port.port_no)
            if found_host
            else (None, None)
        )

    def __find_next_hop_port(self, src_switch_id, dst_switch_id):
        """
        Finds the port which connects the source switch to the next hop switch in the path to the
        destination switch.
        :param src_switch_id: The ID of the source switch.
        :param dst_switch_id: The ID of the destination switch.
        :return: The port number of the next hop switch.
        """
        # Build the network model.
        model = nx.DiGraph()
        for link in get_all_link(self.app):
            model.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        # Find the shortest path between the source and destination switches.
        path = nx.shortest_path(model, src_switch_id, dst_switch_id)

        # Get the first link in the path.
        first_link = model[path[0]][path[1]]
        # Return the port number of the first link.
        return first_link["port"]

    def find_output_port(self, src_switch, dst_mac):
        """
        Finds the output port to which the packet should be sent based on the destination MAC
        address.
        :param src_switch: The object representing the source switch.
        :param dst_mac: The destination MAC address.
        :return: The output port number.
        """
        # Find the switch that has the host with the specified MAC address connected to it.
        (dst_switch_id, dst_switch_port) = self.__find_switch_by_host_mac(dst_mac)

        # If the host is not found, return None.
        if dst_switch_id is None:
            return None

        # If the host is directly connected to the source switch, return the port number of the
        # host.
        if dst_switch_id == src_switch.id:
            return dst_switch_port

        # Otherwise, find the next hop port in the path to the destination switch.
        return self.__find_next_hop_port(src_switch.id, dst_switch_id)


class BabyElephantWalk(app_manager.RyuApp):
    """Main class of the Ryu application. It contains the event handlers and - therefore - the
    main logic of the controller. It serves as the entry point for the SDN app."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BabyElephantWalk, self).__init__(*args, **kwargs)
        # Initialize the MessageFactory with the Ryu application instance.
        self.message_factory = MessageFactory(self)
        # Initialize the NetworkTopology with the Ryu application instance.
        self.network_topology = NetworkTopology(self)

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, ev):
        """Handler for the "Switch Features" event.
        This event is triggered when a switch connects to the controller.
        """
        # Retrive the switch object from the event. Send to it the default configuration.
        switch = ev.msg.datapath
        switch.send_msg(self.message_factory.default_configuration(switch))

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        """Handler for the "Packet In" event.
        This event is triggered when a packet is received by the switch and sent to the controller.
        """
        # Retrive the message and the switch object from the event.
        ofmessage = ev.msg
        switch = ofmessage.datapath

        # Extract the packet from the message. Parse it to get the Ethernet header.
        pkt_in = packet.Packet(ofmessage.data)
        eth_in = pkt_in.get_protocol(ethernet.ethernet)

        ### L2 Manipulation ###

        # If the packet is an ARP request act as a proxy and reply to it.
        if eth_in.ethertype == ether_types.ETH_TYPE_ARP:
            fm_arp_reply = self.message_factory.arp_proxy(ofmessage)
            if fm_arp_reply is not None:
                switch.send_msg(fm_arp_reply)
            return

        # Drop spurious broadcast traffic.
        if eth_in.dst == "ff:ff:ff:ff:ff:ff":
            return

        ### L3 Manipulation ###

        # If the packet is not an IPv4 packet ignore it.
        if eth_in.ethertype != ether_types.ETH_TYPE_IP:
            return

        # If the packet is an IPv4 packet, find the output port to which the packet should be sent
        # based on the destination MAC address.
        output_port = self.network_topology.find_output_port(switch, eth_in.dst)
        if output_port is None:
            return

        fm_pkt_forward = self.message_factory.forward_packet(
            switch, output_port, ofmessage
        )
        switch.send_msg(fm_pkt_forward)
