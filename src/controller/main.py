"""Baby Elephant Walk - Ryu SDN Application"""

from abc import ABC, abstractmethod
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3, inet
from ryu.topology.api import get_all_link, get_all_host, event
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, tcp
from ryu.lib import hub
import networkx as nx

from config import (
    TCP_STREAM_VOLUME_THRESHOLD,
    TCP_TIMEOUT_TRACKING,
    TCP_CONNECTION_TIMEOUT,
    TCP_FORWARDING_RULE_PRIORITY,
    LOG_LEVEL_REMAP,
    TOPOLOGY_CACHING,
)


class MessageFactory:
    """Class used to generate OpenFlow messages (FlowMod, PacketOut) to be sent to the switches."""

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

    def arp_proxy(self, arp_req, mac_dst):
        """
        Generates a PacketOut message able to reply to an ARP request, de-facto acting as a proxy.
        :param arp_req: The ARP request packet received by the controller.
        :return: The PacketOut message to be sent to the switch.
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

        # Starts building the ARP reply packet.
        raw_out = packet.Packet()
        # External Ethernet header: the destination MAC address is the source MAC address of the
        # ARP request, the source MAC address is the MAC address of the host that has the IP
        # address specified in the ARP request.
        eth_out = ethernet.ethernet(
            dst=eth_in.src,
            src=mac_dst,
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
            src_mac=mac_dst,
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
            ip_proto=inet.IPPROTO_TCP,
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
            # Timeout: the rule will expire after TCP_CONNECTION_TIMEOUT seconds of inactivity
            # but only if TCP_TIMEOUT_TRACKING is enabled. Otherwise, the rule will never expire.
            idle_timeout=TCP_CONNECTION_TIMEOUT if TCP_TIMEOUT_TRACKING is True else 0,
        )

        return rule


class NetworkTopology(ABC):
    """Class used to represent the network topology."""

    @abstractmethod
    def find_mac_addr_by_host_ip(self, host_ip):
        """
        Finds the MAC address of the host with the specified IP address.
        :param host_ip: The IP address of the host to be found.
        :return: The MAC address of the host.
        """

    @abstractmethod
    def find_output_port(self, src_switch, dst_mac):
        """
        Finds the output port to which the packet should be sent based on the destination MAC
        address.
        :param src_switch: The object representing the source switch.
        :param dst_mac: The destination MAC address.
        :return: The output port number.
        """

    @abstractmethod
    def update_topology_links(self, links):
        """
        Updates the network topology with the specified links.
        :param links: The list of links used to update the network topology.
        :return: A message indicating the outcome of the update.
        """

    @abstractmethod
    def update_topology_hosts(self, hosts):
        """
        Updates the network topology with the specified hosts.
        :param hosts: The list of hosts used to update the network topology.
        :return: A message indicating the outcome of the update.
        """


class QueryingNetworkTopology(NetworkTopology):
    """Class used to represent the network topology (by always querying Ryu first!)."""

    def __init__(self, app):
        """Initializes the QueryingNetworkTopology with the Ryu app itself."""
        self._app = app

    def _find_switch_by_host_mac(self, dst_mac):
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

    def _find_next_hop_port(self, src_switch_id, dst_switch_id):
        """
        Finds the port which connects the source switch to the next hop switch in the path to the
        destination switch.
        :param src_switch_id: The ID of the source switch.
        :param dst_switch_id: The ID of the destination switch.
        :return: The port number on the source switch leading towards the next hop.
        """
        network_model = nx.DiGraph()
        for link in get_all_link(self._app):
            network_model.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)
        # Find the shortest path between the source and destination switches.
        try:
            path = nx.shortest_path(network_model, src_switch_id, dst_switch_id)
        except nx.NetworkXNoPath:
            # No path found between the source and destination switches.
            return None
        except nx.NodeNotFound:
            # One of the switches is not present in the network model.
            return None

        # Get the first link in the path.
        first_link = network_model[path[0]][path[1]]
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
        (dst_switch_id, dst_switch_port) = self._find_switch_by_host_mac(dst_mac)

        # If the host is not found, return None.
        if dst_switch_id is None:
            return None

        # If the host is directly connected to the source switch, return the port number of the
        # host.
        if dst_switch_id == src_switch.id:
            return dst_switch_port

        # Otherwise, find the next hop port in the path to the destination switch.
        return self._find_next_hop_port(src_switch.id, dst_switch_id)

    # pylint: disable=unused-argument
    def update_topology_links(self, links):
        """
        Updates the network topology with the specified links.
        :param links: Unused. Left here to keep the API consistent.
        :return: A message informing that caching is not used in this implementation.
        """
        return "Detected a topology update event. Caching is currently disabled."

    # pylint: disable=unused-argument
    def update_topology_hosts(self, hosts):
        """
        Updates the network topology with the specified hosts.
        :param hosts: Unused. Left here to keep the API consistent.
        :return: A message informing that caching is not used in this implementation.
        """
        return "Detected a hosts update event. Caching is currently disabled."


class CachingNetworkTopology(NetworkTopology):
    """Class used to represent the network topology (with caching!)."""

    def __init__(self):
        """Initializes the CachingNetworkTopology with an empty network model."""
        self._network_model = nx.DiGraph()
        self._hosts = []

    def _find_switch_by_host_mac(self, dst_mac):
        """
        Finds the switch that has the host with the specified MAC address connected to it.
        :param dst_mac: The MAC address of the host to be found.
        :return: The switch ID that has the host connected to it and the port number of the host.
        """
        found_host = next((host for host in self._hosts if host.mac == dst_mac), None)
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
        found_host = next((host for host in self._hosts if host_ip in host.ipv4), None)
        return found_host.mac if found_host else None

    def _find_next_hop_port(self, src_switch_id, dst_switch_id):
        """
        Finds the port which connects the source switch to the next hop switch in the path to the
        destination switch.
        :param src_switch_id: The ID of the source switch.
        :param dst_switch_id: The ID of the destination switch.
        :return: The port number on the source switch leading towards the next hop.
        """
        # Find the shortest path between the source and destination switches.
        try:
            path = nx.shortest_path(self._network_model, src_switch_id, dst_switch_id)
        except nx.NetworkXNoPath:
            # No path found between the source and destination switches.
            return None
        except nx.NodeNotFound:
            # One of the switches is not present in the network model.
            return None

        # Get the first link in the path.
        first_link = self._network_model[path[0]][path[1]]
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
        (dst_switch_id, dst_switch_port) = self._find_switch_by_host_mac(dst_mac)

        # If the host is not found, return None.
        if dst_switch_id is None:
            return None

        # If the host is directly connected to the source switch, return the port number of the
        # host.
        if dst_switch_id == src_switch.id:
            return dst_switch_port

        # Otherwise, find the next hop port in the path to the destination switch.
        return self._find_next_hop_port(src_switch.id, dst_switch_id)

    def update_topology_links(self, links):
        """
        Updates the network topology with the specified links.
        :param links: The list of links to be added to the network topology.
        :return: A message indicating the outcome of the update.
        """
        success_message = "Topology update successful. Ryu has provided a valid graph."
        failture_message = "Topology update failed. Ryu has provided an invalid graph."

        # First, the provided link list cannot be empty. If it is empty, the update is rejected.
        if len(links) == 0:
            return failture_message

        # Second, all the already known links must be present (as-is) in the provided list. If not,
        # the update cannot be accepted.

        # Build a new network model based on the provided links.
        network_model = nx.DiGraph()
        for link in links:
            network_model.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        # Check if the new network model is a superset of the current one. We should focus on
        # checking the nodes and edges only, not the attributes.
        if set(self._network_model.nodes).issubset(set(network_model.nodes)) and set(
            self._network_model.edges
        ).issubset(set(network_model.edges)):
            self._network_model = network_model
            return success_message

        return failture_message

    def update_topology_hosts(self, hosts):
        """
        Updates the network topology with the specified hosts.
        :param hosts: The list of hosts to be added to the network topology.
        :return: A message indicating the outcome of the update.
        """
        success_message = "Hosts update successful. Ryu has provided a valid set."
        failture_message = "Hosts update failed. Ryu has provided an invalid set."

        # First, the provided host list cannot be empty. If it is empty, the update is rejected.
        if len(hosts) == 0:
            return failture_message

        # Second, all the already known hosts must be present (as-is) in the provided list. If not,
        # the update cannot be accepted.

        for old_host in self._hosts:
            # We need to check that the host is present and that the MAC address, dpid and port are
            # still the same, otherwise the update is rejected.

            # Check first if the host is present.
            new_host = next((host for host in hosts if host.mac == old_host.mac), None)
            if new_host is None:
                return failture_message

            # Check now if the dpid and port are still the same.
            if (
                new_host.port.dpid != old_host.port.dpid
                or new_host.port.port_no != old_host.port.port_no
            ):
                return failture_message

        # If the update is accepted, update the network topology with the new hosts.
        self._hosts = hosts

        return success_message


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
            self.accelerated_switches = set()
            self.counting_switch = None
            self.is_active = True

    def __init__(self):
        """Initializes the ConnectionManager with an empty list of connections."""
        self._connections = {}

    def _canonicalize(self, ip_a, port_a, ip_b, port_b):
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
        key = self._canonicalize(ip_a, port_a, ip_b, port_b)

        # Try to retrieve the connection from the dictionary.
        tcp_conn = self._connections.get(key)
        if tcp_conn is None:
            # The connection does not exist, create a new one!
            tcp_conn = self.Connection(ip_a, port_a, ip_b, port_b)
            self._connections[key] = tcp_conn
        return tcp_conn

    def cleanup_connections(self):
        """This method is meant to be called periodically to clean up connections that are not
        active anymore. Two invocations of this method are needed to remove any connection:
        the first marks all connection as inactive: then, time passes and if a packet is received
        by the controller this flag is reset. The second invocation removes all the still inactive
        communications and sets again the is_active bit to False ensuring that the loop can
        continue.
        :returns : A tuple containing the number of active and inactive connections.
        """
        active_connections = 0
        inactive_connections = 0

        # Take a snapshot of the current keys to avoid errors while iterating.
        for key in list(self._connections.keys()):
            # Retrieve the connection object from the dictionary.
            connection = self._connections[key]
            if connection.is_active:
                # If the connection is active, mark it as inactive.
                connection.is_active = False
                active_connections += 1
            else:
                # If the connection is inactive, remove it from the dictionary.
                self._connections.pop(key, None)
                inactive_connections += 1

        return active_connections, inactive_connections


class ParametricLogger:
    """Class used to dynamically steer the logging level of our application.
    This class exists because Ryu does not support different logging levels for multiple
    applications thus allowing external software to spam our logs with useless information.
    """

    def __init__(self, logger, level_mapping=None):
        """Initializes the ParametricLogger class with the provided logger and the desired
        logging level re-mapping.
        :param logger: The logger object that will be used to log messages.
        :param level_mapping: A dictionary that maps the fictious logging level used in the
        application to the actual desired logging level
        """
        self._logger = logger
        self._level_mapping = level_mapping or {}

        # Extract the logging methods from the logger object.
        # This will make more sense later on.
        self._log_methods = {
            "debug": self._logger.debug,
            "info": self._logger.info,
            "warning": self._logger.warning,
            "error": self._logger.error,
            "critical": self._logger.critical,
        }

    def _log(self, original_level, message, *args, **kwargs):
        """The class receives a log call with a specified logging level. If _level_mapping is not
        None, the original logging level is mapped to the desired new one. The proper logging
        method is then retrieved and called with the message and the arguments.
        :param original_level: The original logging level of the message.
        :param message: The message to be logged.
        :param args: The arguments to be passed to the logging object.
        :param kwargs: The keyword arguments to be passed to the logging object.
        """
        # Eg. We got a log call for level "info" but we want it to become "warning" instead.
        # This mapping is explicitly defined in the _level_mapping dictionary. We can then retrieve
        # the desired logging level and retrieve the corresponding logging method. If the mapping
        # is not defined, we just use the original logging level.
        new_logging_level = self._level_mapping.get(original_level, original_level)
        # Is not really needed to have a default value here because the mapping is always defined.
        # This is done surely to be safe.
        new_log_method = self._log_methods.get(new_logging_level, self._logger.debug)
        # Execute the logging.
        new_log_method(message, *args, **kwargs)

    def debug(self, message, *args, **kwargs):
        """Logs a "debug" message."""
        self._log("debug", message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        """Logs an "info" message."""
        self._log("info", message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        """Logs a "warning" message."""
        self._log("warning", message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        """Logs an "error" message."""
        self._log("error", message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        """Logs a "critical" message."""
        self._log("critical", message, *args, **kwargs)


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
        # Initialize a new NetworkTopology instance.
        if TOPOLOGY_CACHING is True:
            self._network_topology = CachingNetworkTopology()
        else:
            self._network_topology = QueryingNetworkTopology(self)
        # Initialize a new MessageFactory instance.
        self._message_factory = MessageFactory()
        # Initialize a new ConnectionManager instance.
        self._connection_manager = ConnectionManager()
        # Override the default logger object to use our custom ParametricLogger class.
        self._logger = ParametricLogger(self.logger, LOG_LEVEL_REMAP)
        # Log the initialization of the application.
        self._logger.info("init: BabyElephantWalk SDN application initialized.")
        if TCP_TIMEOUT_TRACKING is True:
            # Start a timer to periodically clean up inactive connections.
            self._connections_cleanup_timer = hub.spawn(self.handle_connections_cleanup)

    def handle_connections_cleanup(self):
        """Periodically calls the cleanup_connections method of the ConnectionManager instance to
        clean up inactive connections. This method is not really running in a thread: Ryu just
        add a special event to the event queue that triggers this method. We are thread-safe because
        there is not really any concurrency...
        """
        self._logger.info(
            "connections_cleanup: Global connections cleanup timer activated."
        )
        while True:
            # Do stuff...
            active_connections, inactive_connections = (
                self._connection_manager.cleanup_connections()
            )
            self._logger.info(
                "connections_cleanup: Found %d active communications. Removed %d "
                "inactive/offloaded connections.",
                active_connections,
                inactive_connections,
            )
            # Take a nap...
            hub.sleep(TCP_CONNECTION_TIMEOUT)

    # If needed, also EventSwitchEnter/EventSwitchLeave/EventSwitchReconnected could be used to
    # track a variation in the network topology. This is not done now because we assume that a
    # variation of the switches also implies a variation of the links. Edge case: a single switch
    # without any link is connected to the controller.
    # pylint: disable=unused-argument
    @set_ev_cls(event.EventLinkAdd, CONFIG_DISPATCHER)
    @set_ev_cls(event.EventLinkDelete, CONFIG_DISPATCHER)
    def handle_link_update(self, ev):
        """Handler for the "Link Update" event.
        This event should be triggered when a link is added/removed from the network topology.
        """
        # Asks Ryu to retrieve all the links present in the network.
        links = get_all_link(self)
        # Asks the NetworkTopology instance to update the network topology with the new links.
        result = self._network_topology.update_topology_links(links)
        # Log the outcome of the update.
        self._logger.info("link_update: %s", result)

    # As per documentation, EventHostDelete is ignored due to being not implemented correctly.
    # pylint: disable=unused-argument
    @set_ev_cls(event.EventHostAdd, CONFIG_DISPATCHER)
    @set_ev_cls(event.EventHostMove, CONFIG_DISPATCHER)
    def handle_host_update(self, ev):
        """Handler for the "Host Update" event.
        This event should be triggered when a host is added/removed from the network topology.
        """
        # Asks Ryu to retrieve all the hosts present in the network.
        hosts = get_all_host(self)
        # Asks the NetworkTopology instance to update the network topology with the new hosts.
        result = self._network_topology.update_topology_hosts(hosts)
        # Log the outcome of the update.
        self._logger.info("host_update: %s", result)

    # pylint: disable=no-member
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, ev):
        """Handler for the "Switch Features" event.
        This event is triggered when a switch connects to the controller.
        :param ev: The event object containing the switch features.
        """
        # Retrive the switch object from the event. Construct and send to it the default
        # configuration.
        switch = ev.msg.datapath
        switch.send_msg(self._message_factory.default_configuration(switch))
        # Log the connection of the switch.
        self._logger.info(
            "switch_features: Switch %s connected, default configuration sent.",
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
            arp_in = pkt_in.get_protocol(arp.arp)

            # If the packet is not an ARP request, ignore it.
            if arp_in.opcode != arp.ARP_REQUEST:
                self._logger.warning(
                    "packet_in: ARP packet received from %s. "
                    "Ignoring the packet: not an ARP request.",
                    eth_in.src,
                )
                return

            # Get the MAC address of the host specified in the ARP request by its IP address.
            ip_dst = arp_in.dst_ip
            mac_dst = self._network_topology.find_mac_addr_by_host_ip(ip_dst)
            # Ensure that we have a valid MAC address.
            if mac_dst is not None:
                # Build the PacketOut message to reply to the ARP request and send it to the switch.
                fm_arp_reply = self._message_factory.arp_proxy(ofmessage, mac_dst)
                switch.send_msg(fm_arp_reply)
                self._logger.info(
                    "packet_in: ARP request received from %s for IP %s. "
                    "Host found, replying with MAC %s.",
                    eth_in.src,
                    ip_dst,
                    mac_dst,
                )
            else:
                self._logger.warning(
                    "packet_in: ARP request received from %s for IP %s. "
                    "Unable to reply: host not known.",
                    eth_in.src,
                    ip_dst,
                )

            return

        # Drop spurious broadcast traffic.
        if eth_in.dst == "ff:ff:ff:ff:ff:ff":
            self._logger.warning(
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
            # Deliberately NOT logging this event in order to avoid spamming the logs.
        else:
            # Unable to find a route to the destination MAC address. Dropping the packet.
            self._logger.warning(
                "packet_in: Unable to find a route from switch %s to host %s. Dropping the packet.",
                switch.id,
                eth_in.dst,
            )
            return

        ### L3 Manipulation ###

        # We know for sure that the packet is an IPv4 packet, it will also be a TCP packet?
        ip_in = pkt_in.get_protocol(ipv4.ipv4)
        if ip_in.proto == inet.IPPROTO_TCP:
            # The traffic is a TCP packet, let's parse it.
            tcp_in = pkt_in.get_protocol(tcp.tcp)

            # Retrieve the connection from the ConnectionManager.
            tcp_conn = self._connection_manager.retrieve_connection(
                ip_in.src, tcp_in.src_port, ip_in.dst, tcp_in.dst_port
            )

            # If the connection is brand new, log it.
            if tcp_conn.volume == 0:
                self._logger.info(
                    "packet_in: New TCP connection detected: %s:%s <-> %s:%s. "
                    "Monitoring started.",
                    tcp_conn.ip_a,
                    tcp_conn.port_a,
                    tcp_conn.ip_b,
                    tcp_conn.port_b,
                )
                tcp_conn.counting_switch = switch.id

            # In any case, we have a packet that belongs to a TCP connection. This means that the
            # connection is active. Make sure to keep the flag is_active set to True.
            tcp_conn.is_active = True
            # N.B: A connection can be removed from ConnectionManager - due to packet not arriving
            # to the controller - but still be active on the switches. This is intended: we have
            # offloaded the connection to the dataplane and its not our job to track it anymore.

            # Update the volume of the connection.
            if tcp_conn.counting_switch == switch.id:
                # If the connection is being monitored by the current switch, update the volume.
                # This is done to avoid counting the traffic multiple times.
                tcp_conn.volume += ip_in.total_length

            # If the volume of the connection is greater than the threshold, we can install a rule
            # to forward the TCP stream directly bypassing the controller.
            if tcp_conn.volume >= TCP_STREAM_VOLUME_THRESHOLD:
                # If the connection is already directly forwarded by the switch we don't need to do
                # anything.
                if switch.id in tcp_conn.accelerated_switches:
                    self._logger.debug(
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
                    self._logger.warning(
                        "packet_in: Unable to find a route from switch %s to host %s. "
                        "Aborting forwarding rule installation.",
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
                    self._logger.warning(
                        "packet_in: Unable to find a route from switch %s to host %s. "
                        "Aborting forwarding rule installation.",
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
                self._logger.info(
                    "packet_in: Rule installed for %s:%s -> %s:%s traffic on switch %s.",
                    endp_a_ip,
                    endp_a_port,
                    endp_b_ip,
                    endp_b_port,
                    switch.id,
                )

                switch.send_msg(fm_rule_b_to_a)
                self._logger.info(
                    "packet_in: Rule installed for %s:%s -> %s:%s traffic on switch %s.",
                    endp_b_ip,
                    endp_b_port,
                    endp_a_ip,
                    endp_a_port,
                    switch.id,
                )

                # Add the switch to the list of switches that are forwarding the TCP stream
                tcp_conn.accelerated_switches.add(switch.id)
