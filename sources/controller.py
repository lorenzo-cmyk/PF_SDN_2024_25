from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from logging import Logger, getLogger

class MessageFactory:
    @staticmethod
    def defaultSwitchConfiguration(switch):
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


class BabyElephantWalk(app_manager.RyuApp):
    # OFP version definition.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    logger: Logger

    def __init__(self, *args, **kwargs):
        """ Default controller contructor."""
        super(BabyElephantWalk, self).__init__(*args, **kwargs)
        # Initialize the MesasgeFactory object.
        self.message_factory = MessageFactory()
        self.logger = getLogger("BabyElephantWalk")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _eventHandler_switchFeatures(self, ev):
        """ Handle the switch feature announcement event."""
        switch = ev.msg.datapath
        mod = MessageFactory.defaultSwitchConfiguration(switch)

        # Send the message to the switch.
        switch.send_msg(mod)
        self.logger.info(f"Switch {switch.id} initialized with default configuration.")

    