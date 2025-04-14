"""Baby Elephant Walk - Ryu SDN Application"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp
import networkx as nx


# Priority of the TCP forwarding rules.
TCP_FORWARDING_RULE_PRIORITY = 100
# Threshold for the TCP stream volume: if the volume is greater than this value, a rule will be
# installed to forward the TCP stream directly bypassing the controller. Value is in bytes.
TCP_STREAM_VOLUME_THRESHOLD = 25 * 1000 * 1000 # 25 MB
# Timeout for the TCP forwarding rules: if the connection is not used for this amount of time, it
# will be removed from the switch or from the controller. Value is in seconds.
TCP_CONNECTION_TIMEOUT = 20


class MessageFactory:
    """Class used to generate OpenFlow messages (FlowMod, PacketOut) to be sent to the switches."""

    def __init__(self, network_topology):
        """Initializes the MessageFactory with a NetworkTopology class instance.
        :param network_topology: The NetworkTopology instance itself.
        """
        self._network_topology = network_topology

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
        Generates a PacketOut message able to reply to an ARP request, de-facto acting as a proxy.
        :param arp_req: The ARP request packet received by the controller.
        :return: The PacketOut message to be sent to the switch. If the host is not found, None is
                 returned.
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
            return None

        # Finds the MAC address of the host that has the IP address specified in the ARP request.
        # If the host is not found, return None.
        target_mac_address = self._network_topology.find_mac_addr_by_host_ip(arp_in.dst_ip)
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

        # Build the PacketOut message to inscruct the switch to send the ARP reply that we have just
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
        Generates a PacketOut message to forward the packet to the specified output port.
        :param switch: The switch to which the PacketOut message will be sent.
        :param out_port: The output port to which the packet will be forwarded.
        :param pkt: The packet to be forwarded.
        :return: The PacketOut message to be sent to the switch.
        """
        # Retrive the OpenFlow parser object from the switch.
        ofparser = switch.ofproto_parser

        # Build the PacketOut message to instruct the switch to forward the packet to the specified
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

    def forward_tcp_stream_configuration(
        self, switch, ip_scr, port_src, ip_dst, port_dst, out_port
    ):
        """
        Generates a FlowMod message that instructs the switch to forward a TCP stream, identified
        by the IPs and ports combination, to the specified output port.
        :param switch: The switch on which the rule will be installed.
        :param ip_scr: The source IP address of the TCP stream.
        :param port_src: The TCP source port.
        :param ip_dst: The destination IP address of the TCP stream.
        :param port_dst: The TCP destination port.
        :param out_port: The output port to which the TCP stream will be forwarded.
        :return: The FlowMod message to be sent to the switch.
        """
        # Retrieve the OpenFlow protocol object and relative parser from the switch.
        ofprotocol = switch.ofproto
        ofparser = switch.ofproto_parser

        # Build the FlowMod message to instruct the switch to forward the TCP stream to the
        # specified output port.
        # Match: match the TCP stream based on the IPs and ports combination.
        match = ofparser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_scr,
            ipv4_dst=ip_dst,
            ip_proto=6,  # IPv4 protocol 6 is TCP
            tcp_src=port_src,
            tcp_dst=port_dst,
        )
        # Instructions: apply the action: send everything to the specified output port.
        instructions = [
            ofparser.OFPInstructionActions(
                ofprotocol.OFPIT_APPLY_ACTIONS,
                [ofparser.OFPActionOutput(out_port)],
            )
        ]
        # Rule: build the FlowMod message ready to be sent to the switch.
        rule = ofparser.OFPFlowMod(
            datapath=switch,
            priority=TCP_FORWARDING_RULE_PRIORITY,
            match=match,
            instructions=instructions,
            # Timeout: the rule will expire after TCP_CONNECTION_TIMEOUT seconds of inactivity.
            idle_timeout=TCP_CONNECTION_TIMEOUT,
        )

        return rule


class NetworkTopology:
    """Class used to represent the network topology."""

    def __init__(self, app):
        """Initializes the NetworkTopology with the Ryu application instance.
        :param app: The Ryu application instance.
        """
        self._app = app

    def __find_switch_by_host_mac(self, dst_mac):
        """
        Finds the switch that has the host with the specified MAC address connected to it.
        :param dst_mac: The MAC address of the host to be found.
        :return: The switch ID that has the host connected to it and the port number of the host.
        """
        found_host = next(
            (host for host in get_all_host(self._app) if host.mac == dst_mac), None
        )
        return (
            (found_host.port.dpid, found_host.port.port_no)
            if found_host
            else (None, None)
        )
    
    def find_mac_addr_by_host_ip(self, host_ip):
        """
        Finds the MAC address of the host with the specified IP address.
        :param host_ip: The IP address of the host to be found.
        :return: The MAC address of the host.
        """
        found_host = next(
            (host for host in get_all_host(self._app) if host_ip in host.ipv4), None
        )
        return found_host.mac if found_host else None

    def __find_next_hop_port(self, src_switch_id, dst_switch_id):
        """
        Finds the port which connects the source switch to the next hop switch in the path to the
        destination switch.
        :param src_switch_id: The ID of the source switch.
        :param dst_switch_id: The ID of the destination switch.
        :return: The port number on the source switch leading towards the next hop.
        """
        # Build the network model.
        model = nx.DiGraph()
        for link in get_all_link(self._app):
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


class ConnectionManager:
    """Class used to manage TCP connections between hosts."""

    class Connection:
        """Class used to represent a TCP connection between two hosts."""

        def __init__(self, ip_a, port_a, ip_b, port_b):
            """Initializes a TCP connection between the specified hosts.
            :param ip_a: The IP address of the first host.
            :param port_a: The port number of the first host.
            :param ip_b: The IP address of the second host.
            :param port_b: The port number of the second host.
            """
            self.ip_a = ip_a
            self.port_a = port_a
            self.ip_b = ip_b
            self.port_b = port_b
            self.volume = 0
            self.ovs_accel_switches = []

    def __init__(self):
        """Initializes the ConnectionManager with an empty list of connections."""
        self._connections = {}

    def __canonicalize(self, ip_a, port_a, ip_b, port_b):
        """Returns the canonical representation of a TCP connection between two hosts.
        :param ip_a: The IP address of the first host.
        :param port_a: The port number of the first host.
        :param ip_b: The IP address of the second host.
        :param port_b: The port number of the second host.
        :return: A tuple representing the canonical representation of the TCP connection.
        """
        uplink = (ip_a, port_a, ip_b, port_b)
        downlink = (ip_b, port_b, ip_a, port_a)
        # The canonical representation of a TCP connection is the one with the lowest tuple.
        # This is done to avoid having two different representations of the same connection.
        return min(uplink, downlink)

    def retrieve_connection(self, ip_a, port_a, ip_b, port_b):
        """Retrieve the TCP connection object from the specified parameters.
        If the connection does not exist, it creates a new one on the fly.
        :param ip_a: The IP address of the first host.
        :param port_a: The port number of the first host.
        :param ip_b: The IP address of the second host.
        :param port_b: The port number of the second host.
        :return: The TCP connection object.
        """
        # Get the canonical representation of the TCP connection.
        key = self.__canonicalize(ip_a, port_a, ip_b, port_b)

        # Try to retrieve the connection from the dictionary.
        tcp_conn = self._connections.get(key)
        if tcp_conn is None:
            # The connection does not exist, create a new one!
            tcp_conn = self.Connection(ip_a, port_a, ip_b, port_b)
            self._connections[key] = tcp_conn
        return tcp_conn


class BabyElephantWalk(app_manager.RyuApp):
    """Main class of the Ryu application. It contains the event handlers and - therefore - the
    main logic of the controller. It serves as the entry point for the SDN app."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Initializes the BabyElephantWalk Ryu application.
        :param args: The arguments to be passed to the Ryu application.
        :param kwargs: The keyword arguments to be passed to the Ryu application.
        """
        super().__init__(*args, **kwargs)
        # Initialize the NetworkTopology with the Ryu application instance.
        self._network_topology = NetworkTopology(self)
        # Initialize the MessageFactory with the NetworkTopology instance.
        self._message_factory = MessageFactory(self._network_topology)
        # Initialize a new ConnectionManager instance.
        self._connection_manager = ConnectionManager()
        # Log the initialization of the application.
        self.logger.info("init: BabyElephantWalk application initialized!")

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, ev):
        """Handler for the "Switch Features" event.
        This event is triggered when a switch connects to the controller.
        :param ev: The event object containing the switch features.
        """
        # Retrive the switch object from the event. Send to it the default configuration.
        switch = ev.msg.datapath
        switch.send_msg(self._message_factory.default_configuration(switch))
        # Log the connection of the switch.
        self.logger.info(
            "switch_features: Switch %s connected. Default configuration has been sent.",
            switch.id,
        )

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, ev):
        """Handler for the "Packet In" event.
        This event is triggered when a packet is received by the switch and sent to the controller.
        :param ev: The event object containing the packet information.
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
            fm_arp_reply = self._message_factory.arp_proxy(ofmessage)
            if fm_arp_reply is not None:
                switch.send_msg(fm_arp_reply)
            else:
                self.logger.warning(
                    "packet_in: ARP request received from %s for IP %s. "
                    "Unable to reply: host not known.",
                    eth_in.src,
                    pkt_in.get_protocol(arp.arp).dst_ip,
                )
            return

        # Drop spurious broadcast traffic.
        if eth_in.dst == "ff:ff:ff:ff:ff:ff":
            self.logger.warning(
                "packet_in: Spurious broadcast traffic received from %s. Dropping the packet.",
                eth_in.src,
            )
            return

        # If the packet is not an IPv4 packet ignore it.
        if eth_in.ethertype != ether_types.ETH_TYPE_IP:
            # Lots of non-IPv4 traffic is sent to the controller: most of them are LLDP multicast
            # and IPv6 RS packets. We are going to ignore them, this is totally fine.
            # For more information see the following issue on GitHub:
            # https://github.com/TheManchineel/sdn-project/issues/3#issuecomment-2794506696
            # Logging this traffic is pointless, it's just noise and it going to spam the logs.
            return

        # If the packet is an IPv4 packet, find the output port to which the packet should be sent
        # based on the destination MAC address and forward it.
        output_port = self._network_topology.find_output_port(switch, eth_in.dst)
        if output_port is not None:
            fm_pkt_forward = self._message_factory.forward_packet(
                switch, output_port, ofmessage
            )
            switch.send_msg(fm_pkt_forward)
        else:
            # Unable to find a route to the destination MAC address. Dropping the packet.
            self.logger.warning(
                "packet_in: Unable to find a route from switch %s to host %s. Dropping the packet.",
                switch.id,
                eth_in.dst,
            )
            return

        ### L3 Manipulation ###

        # We know for sure that the packet is an IPv4 packet, it will also be a TCP packet?
        ip_in = pkt_in.get_protocol(ipv4.ipv4)
        if ip_in.proto == 6:
            # The traffic is a TCP packet, let's parse it.
            tcp_in = pkt_in.get_protocol(tcp.tcp)

            # Retrieve the connection from the ConnectionManager.
            tcp_conn = self._connection_manager.retrieve_connection(
                ip_in.src, tcp_in.src_port, ip_in.dst, tcp_in.dst_port
            )

            # If the connection is brand new, log it.
            if tcp_conn.volume == 0:
                self.logger.info(
                    "packet_in: New TCP connection detected: %s:%s <-> %s:%s. "
                    "Started monitoring it.",
                    tcp_conn.ip_a,
                    tcp_conn.port_a,
                    tcp_conn.ip_b,
                    tcp_conn.port_b,
                )

            # Update the volume of the connection.
            tcp_conn.volume += len(pkt_in.data)

            # If the volume of the connection is greater than the threshold, we can install a rule
            # to forward the TCP stream directly bypassing the controller.
            if tcp_conn.volume >= TCP_STREAM_VOLUME_THRESHOLD:
                # If the connection is already directly forwarded by the switch we don't need to do
                # anything.
                if switch.id in tcp_conn.ovs_accel_switches:
                    self.logger.debug(
                        "packet_in: OpenFlow rule for forwarding traffic between %s:%s <-> %s:%s "
                        "is being installed on switch %s. Forwarding manually in the meantime.",
                        tcp_conn.ip_a,
                        tcp_conn.port_a,
                        tcp_conn.ip_b,
                        tcp_conn.port_b,
                        switch.id,
                    )
                    return

                # Convention: Enpoint A is the host that has sent the current packet while
                # Endpoint B is the host will receive it. Most of the variables here are redundant
                # but the are kept for clarity.
                endp_a_mac, endp_a_ip, endp_a_port = (
                    eth_in.src,
                    ip_in.src,
                    tcp_in.src_port,
                )
                endp_b_mac, endp_b_ip, endp_b_port = (
                    eth_in.dst,
                    ip_in.dst,
                    tcp_in.dst_port,
                )

                # Upstream traffic: A -> B
                a_to_b_phy_port = self._network_topology.find_output_port(
                    switch, endp_b_mac
                )
                # If we are unable to find a route to the destination MAC address abort the rule
                # installation.
                if a_to_b_phy_port is None:
                    self.logger.warning(
                        "packet_in: Unable to find a route from switch %s to host %s. "
                        "Aborting forwarding rule installation!",
                        switch.id,
                        endp_b_mac,
                    )
                    return
                # Build the relative FlowMod message to be sent to the switch.
                fm_rule_a_to_b = self._message_factory.forward_tcp_stream_configuration(
                    switch,
                    endp_a_ip,
                    endp_a_port,
                    endp_b_ip,
                    endp_b_port,
                    a_to_b_phy_port,
                )

                # Downstream traffic: B -> A
                b_to_a_phy_port = self._network_topology.find_output_port(
                    switch, endp_a_mac
                )
                # If we are unable to find a route to the destination MAC address abort the rule
                # installation.
                if b_to_a_phy_port is None:
                    self.logger.warning(
                        "packet_in: Unable to find a route from switch %s to host %s. "
                        "Aborting forwarding rule installation!",
                        switch.id,
                        endp_a_mac,
                    )
                    return
                # Build the relative FlowMod message to be sent to the switch.
                fm_rule_b_to_a = self._message_factory.forward_tcp_stream_configuration(
                    switch,
                    endp_b_ip,
                    endp_b_port,
                    endp_a_ip,
                    endp_a_port,
                    b_to_a_phy_port,
                )

                # Send the FlowMod messages to the switch.
                switch.send_msg(fm_rule_a_to_b)
                self.logger.info(
                    "packet_in: Rule installed for %s:%s -> %s:%s traffic on switch %s.",
                    endp_a_ip,
                    endp_a_port,
                    endp_b_ip,
                    endp_b_port,
                    switch.id,
                )

                switch.send_msg(fm_rule_b_to_a)
                self.logger.info(
                    "packet_in: Rule installed for %s:%s -> %s:%s traffic on switch %s.",
                    endp_b_ip,
                    endp_b_port,
                    endp_a_ip,
                    endp_a_port,
                    switch.id,
                )

                # Add the switch to the list of switches that are forwarding the TCP stream
                tcp_conn.ovs_accel_switches.append(switch.id)
