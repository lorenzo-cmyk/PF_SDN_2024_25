from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp
import networkx as nx

#### Methods used to generate FlowMod messages ####

def flowmod_default_configuration(switch):
    """
    Generates a FlowMod message to configure the switch to send all packets to the controller.
    :param switch: The switch to be configured.
    :return: The FlowMod message to be sent to the switch.
    """
    # Retrieve the OpenFlow protocol object and relative parser from the switch.
    ofprotocol = switch.ofproto
    ofparser = switch.ofproto_parser

    # Default configuration for the switch: sends everything to the controller.
    # Instructions: for each packet, apply the action: send everything to the controller using the OFPP_CONTROLLER port.
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
    # Rule: match everything and apply the instructions. Keep the priority low to avoid conflicts with other rules.
    rule = ofparser.OFPFlowMod(
        datapath=switch,
        priority=0,
        # Match: match everything (wildcard).
        match=ofparser.OFPMatch(),
        instructions=instructions,
    )

    return rule

def flowmod_arp_proxy(app, arp_req):
    """
    Generates a FlowMod message to reply to an ARP request with the MAC address of the host that has the IP address specified in the ARP request.
    :param app: The Ryu application instance.
    :param arp_req: The ARP request packet received by the controller.
    :return: The FlowMod message to be sent to the switch.
    """
    # Retrieve the OpenFlow protocol object and relative parser from the switch.
    # The switch itself is extracted from the ARP request.
    switch = arp_req.datapath
    ofprotocol = switch.ofproto
    ofparser = switch.ofproto_parser

    # Parse the ARP request: starts from the raw byte stream received by the controller and extracts Ethernet and ARP informations.
    raw_in = packet.Packet(arp_req.data)
    eth_in = raw_in.get_protocol(ethernet.ethernet)
    arp_in = raw_in.get_protocol(arp.arp)

    # Handle only ARP requests, ignore all other types of ARP packets.
    if arp_in.opcode != arp.ARP_REQUEST:
        return

    # Finds the MAC address of the host that has the IP address specified in the ARP request.
    # If the host is not found, the function returns without doing anything.
    target_mac_address = next(
        (host.mac for host in get_all_host(app) if arp_in.dst_ip in host.ipv4), None
    )
    if target_mac_address is None:
        return None

    # Starts building the ARP reply packet.
    raw_out = packet.Packet()
    # External Ethernet header: the destination MAC address is the source MAC address of the ARP request, the source MAC address is the MAC address of the host that has the IP address specified in the ARP request.
    eth_out = ethernet.ethernet(
        dst=eth_in.src,
        src=target_mac_address,
        # Ethernet type: ARP
        ethertype=ether_types.ETH_TYPE_ARP,
    )
    # ARP header: the opcode is ARP_REPLY, the source MAC address is the MAC address of the host that has the IP address specified in the ARP request, the source IP address is the IP address specified in the ARP request, the destination MAC address is the source MAC address of the ARP request, and the destination IP address is the IP address specified in the ARP request.
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

    # Build the FlowMod message to inscruct the switch to send the ARP reply that we have just built.
    arp_reply = ofparser.OFPPacketOut(
        datapath=switch,
        buffer_id=ofprotocol.OFP_NO_BUFFER,
        in_port=ofprotocol.OFPP_CONTROLLER,
        # The ARP reply is sent to the port from which the ARP request was received.
        actions=[ofparser.OFPActionOutput(arp_req.match["in_port"])],
        data=raw_out.data,
    )

    return arp_reply


class HopByHopSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # tutti i pacchetti al controllore
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        datapath.send_msg(flowmod_default_configuration(datapath))

    # trova switch destinazione e porta dello switch
    def find_destination_switch(self,destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None,None)

    def find_next_hop_to_destination(self,source_id,destination_id):
        net = nx.DiGraph()
        for link in get_all_link(self):
            net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(
            net,
            source_id,
            destination_id
        )

        first_link = net[ path[0] ][ path[1] ]

        return first_link['port']

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # se ARP esegui proxy arp
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            out = flowmod_arp_proxy(self, msg)
            if out is not None:
                # invia il pacchetto ARP reply al switch
                datapath.send_msg(out)

            return

        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        destination_mac = eth.dst

        # trova switch destinazione
        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)

        # host non trovato
        if dst_dpid is None:
            # print "DP: ", datapath.id, "Host not found: ", pkt_ip.dst
            return

        if dst_dpid == datapath.id:
            # da usare se l'host e' direttamente collegato
            output_port = dst_port    
        else:
            # host non direttamente collegato
            output_port = self.find_next_hop_to_destination(datapath.id,dst_dpid)

        # print "DP: ", datapath.id, "Host: ", pkt_ip.dst, "Port: ", output_port

        # inoltra il pacchetto corrente
        actions = [ parser.OFPActionOutput(output_port) ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
