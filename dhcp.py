# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import dhcp, udp, ipv4
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import addrconv
#from helper import ofp_helper

import threading
import time



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.dp = {}

        self.messages={1: "DHCP DISCOVER", 2: "DHCP OFFER", 3:"DHCP REQUEST", 4 : "DHCP ACK"}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        self.dp[str(datapath.id)] = datapath
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def received_discover(self,datapath, dhcpPacket, in_port):
        print("sme tu")
        dhcp_offer_msg_type = '\x02'

        msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                 value=dhcp_offer_msg_type)
        options = dhcp.options(option_list=[msg_option])
        hlen = len(addrconv.mac.text_to_bin(dhcpPacket.chaddr))

        newDhcp = dhcp.dhcp(hlen=hlen,
                             op=dhcp.DHCP_BOOT_REPLY,
                             chaddr= dhcpPacket.chaddr,
                             yiaddr="10.88.0.1",
                             giaddr= dhcpPacket.giaddr,
                             xid= dhcpPacket.xid,
                             options=options)

        self.send_dhcp_packet(datapath, newDhcp, in_port)

    def send_dhcp_packet(self, datapath, newPacket, in_port):

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet
                         (src="ff:ff:ff:ff:00:00", dst="ff:ff:ff:ff:ff:ff"))         ########zmenit toto fiasko
        pkt.add_protocol(ipv4.ipv4
                         (src="10.88.0.254", dst="255.255.255.255", proto=17))      ########zmenit toto fiasko
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(newPacket)

       # ofp_helper.send_packet(datapath, pkt, in_port)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        ##########################################################################

        dhcpPacket = None
        dhcpPacket = pkt.get_protocol(dhcp.dhcp)

        if dhcpPacket is not None:
            print("DHCP!!!!! "+str(dhcpPacket))

        if dhcpPacket:
            msgType = ord(dhcpPacket.options.option_list[0].value)
            print(str(self.messages[msgType]))
            if self.messages[msgType] == "DHCP DISCOVER":
                self.received_discover(datapath, dhcpPacket, in_port)







        ##########################################################################
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
