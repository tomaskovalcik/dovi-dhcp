from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from controller import Controller
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, dhcp, ipv4, udp
from ryu.lib import addrconv

class DhcpServer(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    ACK = 4
    DHCP_SERVER_MAC = "aa:bb:cc:dd:ee:ff"
    DHCP_SERVER_IP = "10.0.0.254"

    def __init__(self, *args, **kwargs):
        super(DhcpServer, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(Controller, {Controller.simple_switch_instance_name: self})

        self.messages = {1: "DHCP DISCOVER", 2: "DHCP OFFER", 3: "DHCP REQUEST", 4: "DHCP ACK"}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dhcpPacket = None
        dhcpPacket = pkt.get_protocol(dhcp.dhcp)

        if dhcpPacket:
            msgType = ord(dhcpPacket.options.option_list[0].value)
            print(str(msgType)+" Dosiel")
            if self.messages[msgType] == "DHCP DISCOVER":
                print("sme tutuuuuuuuu")
                self.create_dhcp_packet(eth.src, dhcpPacket, datapath, in_port)
            elif self.messages[msgType] == "DHCP REQUEST":
                self.recieved_request(eth.src, dhcpPacket, datapath, in_port)

    def recieved_request(self, dst_mac,dhcp_lst, dp, port, dst_ip='255.255.255.255'):

        #############################
        pkt = packet.Packet()
        dhcp_ack_msg_type = b'\x05'
        subnet_option = dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                                   value=addrconv.ipv4.text_to_bin('255.255.255.0'))
        gw_option = dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                                value=addrconv.ipv4.text_to_bin('10.0.0.254'))
        time_option = dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                                  value=b'\xFF\xFF\xFF\xFF')
        msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                 value=dhcp_ack_msg_type)
        id_option = dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                                value=addrconv.ipv4.text_to_bin('10.0.0.98'))
        hlen = len(addrconv.mac.text_to_bin(dhcp_lst.chaddr))
        dns_option = dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                                 value=addrconv.ipv4.text_to_bin('4.4.4.4'))
        options = dhcp.options(option_list=[msg_option, id_option,
                               time_option, subnet_option, dns_option,
                               gw_option])

        hlen = len(addrconv.mac.text_to_bin(dhcp_lst.chaddr))
        dhcp_pkt = dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                             hlen=hlen,
                             chaddr=dhcp_lst.chaddr,
                             yiaddr='10.0.0.98',
                             giaddr=dhcp_lst.giaddr,
                             xid=dhcp_lst.xid,
                             options=options)

        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,
                                           dst=dst_mac, src=self.DHCP_SERVER_MAC))
        pkt.add_protocol(ipv4.ipv4(dst=dst_ip, src=self.DHCP_SERVER_IP, proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(dhcp_pkt)
        pkt.serialize()
        self.inject_packet(pkt, dp, port)

        ###############
        #####dorobit databazu pridelinych IP
        ##############################

    def create_dhcp_packet(self, dst_mac,dhcp_lst, dp, port, dst_ip='255.255.255.255'):
        pkt = packet.Packet()
        dhcp_offer_msg_type = b'\x02'
        hlen = len(addrconv.mac.text_to_bin(dhcp_lst.chaddr))
        msg_option = dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                 value=dhcp_offer_msg_type)
        options = dhcp.options(option_list=[msg_option])

        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,
                                           dst=dst_mac, src=self.DHCP_SERVER_MAC))
        pkt.add_protocol(ipv4.ipv4(dst=dst_ip, src=self.DHCP_SERVER_IP, proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(dhcp.dhcp(hlen=hlen,op=dhcp.DHCP_BOOT_REPLY,
                                   yiaddr="10.0.0.98",xid = dhcp_lst.xid,giaddr=dhcp_lst.giaddr,chaddr=dst_mac,options=options))
        ###
        #yiaddr="10.0.0.98" ---IP pre clienta
        ###
        pkt.serialize()
        self.inject_packet(pkt, dp, port)

    def inject_packet(self, pkt, dp, port):
        if dp is None:
            dp = self.switches[0]

        ofproto = dp.ofproto
        if port is None:
            port = ofproto.OFPP_FLOOD

        parser = dp.ofproto_parser
        data = pkt.data
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        dp.send_msg(out)