from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
import networkx as nx
from ryu.lib.packet import packet, ethernet, ether_types, arp


class MessageFactory:
    @staticmethod
    def default_switch_configuration(switch):
        # Retrieve the OpenFlow protocol object from the switch.
        ofprotocol = switch.ofproto
        # Retrieve the parser from the OpenFlow protocol object.
        ofparser = switch.ofproto_parser

        # Default configuration for the switch: sends everything to the controller.
        # Actions: sends everything to the controller using the OFPP_CONTROLLER port.
        actions = [
            ofparser.OFPInstructionActions(
                ofprotocol.OFPIT_APPLY_ACTIONS,
                [
                    ofparser.OFPActionOutput(
                        ofprotocol.OFPP_CONTROLLER, ofprotocol.OFPCML_NO_BUFFER
                    )
                ],
            )
        ]

        # Rule: match everything and apply the actions. Keep the priority low to avoid conflicts with other rules.
        rule = ofparser.OFPFlowMod(
            datapath=switch,
            priority=0,
            # Match: match everything (wildcard).
            match=ofparser.OFPMatch(),
            instructions=actions,
        )

        return rule

    @staticmethod
    def proxy_arp(app, request):
        # Retrive the switch from which the request was received.
        src_switch = request.datapath
        # Retrieve the OpenFlow protocol object from the switch.
        ofprotocol = src_switch.ofproto
        # Retrieve the parser from the OpenFlow protocol object.
        ofparser = src_switch.ofproto_parser

        # Retrieve the port from which the request was received.
        src_port = request.match["in_port"]

        # Retrieve the ARP packet from the request.
        raw_packet = packet.Packet(request.data)
        # Retrieve the ethernet packet from the raw packet.
        ethernet_packet = raw_packet.get_protocol(ethernet.ethernet)
        # Retrieve the ARP packet from the ethernet packet.
        arp_packet = raw_packet.get_protocol(arp.arp)

        # Ensure that the ARP packet is a request.
        if arp_packet.opcode != arp.ARP_REQUEST:
            return

        # Find the MAC address of the host which IP was requested.
        result = [
            host.mac for host in get_all_host(app) if arp_packet.dst_ip in host.ipv4
        ]
        if not result:
            return None

        dst_mac = result[0]

        # Create a new ARP packet with the source MAC address of the host which IP was requested.
        # Create the raw packet to be sent to the switch.
        raw_packet_out = packet.Packet()
        # Create the ethernet packet.
        ethernet_packet_out = ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=ethernet_packet.src,
            src=dst_mac,
        )
        # Create the ARP packet.
        arp_packet_out = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=arp_packet.dst_ip,
            dst_mac=arp_packet.src_mac,
            dst_ip=arp_packet.src_ip,
        )
        # Encapsulate everything in the raw packet.
        raw_packet_out.add_protocol(ethernet_packet_out)
        raw_packet_out.add_protocol(arp_packet_out)
        raw_packet_out.serialize()

        # Build a flow mod message
        message = ofparser.OFPPacketOut(
            datapath=src_switch,
            buffer_id=ofprotocol.OFP_NO_BUFFER,
            in_port=ofprotocol.OFPP_CONTROLLER,
            actions=[ofparser.OFPActionOutput(src_port)],
            data=raw_packet_out.data,
        )

        return message

    @staticmethod
    def forward_packet(message, output_port):
        """Forward the packet to the specified output port."""
        # Retrieve the OpenFlow protocol object from the switch.
        ofprotocol = message.datapath.ofproto
        # Retrieve the parser from the OpenFlow protocol object.
        ofparser = message.datapath.ofproto_parser

        # Create a flow mod message to forward the packet.
        out_message = ofparser.OFPFlowMod(
            datapath=message.datapath,
            buffer_id=message.buffer_id,
            in_port=message.match["in_port"],
            actions=[ofparser.OFPActionOutput(output_port)],
            data=message.data,
        )

        return out_message


class Topology:
    """Class to represent the network topology."""

    def __init__(self, app):
        self.graph = nx.DiGraph()
        self.app = app

    def update_topology(self):
        self.graph.clear()
        for link in get_all_link(self.app):
            self.graph.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

    def find_destination_switch(self, destination_mac_address):
        """Find a switch that has connected to the destination MAC address."""
        result = [
            (host.port.dpid, host.port.port_no)
            for host in filter(
                lambda host: host.mac == destination_mac_address, get_all_host(self.app)
            )
        ]

        return result[0] if result else (None, None)

    def find_next_hop_to_destination(self, source_switch, destination_switch):
        """Find the next hop to the destination switch."""
        if not self.graph.has_node(source_switch) or not self.graph.has_node(
            destination_switch
        ):
            return None

        try:
            path = nx.shortest_path(self.graph, source_switch, destination_switch)
            return self.graph[path[0]][path[1]]["port"]
        except nx.NetworkXNoPath:
            return None


class BabyElephantWalk(app_manager.RyuApp):
    # OFP version definition.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Default controller contructor."""
        super(BabyElephantWalk, self).__init__(*args, **kwargs)
        # Initialize the MesasgeFactory object.
        self.message_factory = MessageFactory()
        self.topology = Topology(self)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _eventHandler_switchFeatures(self, ev):
        """Handle the switch feature announcement event."""
        switch = ev.msg.datapath
        mod = MessageFactory.default_switch_configuration(switch)
        self.topology.update_topology()

        # Send the message to the switch.
        switch.send_msg(mod)
        self.logger.info(f"Switch {switch.id} initialized with default configuration.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _eventHandler_packetIn(self, ev):
        """Handle the packet-in event."""
        # Retrieve the packet from the event.
        packet_in = ev.msg
        # Retrieve the switch from which the packet was received.
        switch = packet_in.datapath
        # Retrieve the OpenFlow protocol object from the switch.
        ofprotocol = switch.ofproto
        # Retrieve the parser from the OpenFlow protocol object.
        ofparser = switch.ofproto_parser

        # Retrieve the port from which the packet was received.
        src_port = packet_in.match["in_port"]

        # Retrieve the raw packet from the event.
        raw_packet = packet.Packet(packet_in.data)
        # Retrieve the ethernet packet from the raw packet.
        ethernet_packet = raw_packet.get_protocol(ethernet.ethernet)

        # Take action based on the ethernet type.

        if ethernet_packet.ethertype == ether_types.ETH_TYPE_ARP:
            # Handle ARP packets.
            message = MessageFactory.proxy_arp(self, packet_in)
            if message:
                switch.send_msg(message)
                self.logger.info(
                    f"ARP request from {ethernet_packet.src} to {ethernet_packet.dst}"
                )
            return
        elif ethernet_packet.ethertype == ether_types.ETH_TYPE_IP:
            # Find the switch, and relative port, that has the host connected the host with the destination MAC address.
            dst_switch, dst_port = self.topology.find_destination_switch(
                ethernet_packet.dst
            )
            if not dst_switch:
                self.logger.info(
                    f"Destination {ethernet_packet.dst} not found. Dropping packet."
                )
                return
            # Find the next hop to the destination switch.
            # If the source switch is the destination switch, we just need to keep notice of the port.
            if switch.id == dst_switch:
                next_hop = dst_port
            else:
                next_hop = self.topology.find_next_hop_to_destination(
                    switch.id, dst_switch
                )

            if not next_hop:
                self.logger.info(
                    f"No path to destination {ethernet_packet.dst}. Dropping packet."
                )
                return
            # Create a flow mod message to forward the packet.
            message = MessageFactory.forward_packet(packet_in, next_hop)
            # Send the message to the switch.
            switch.send_msg(message)
