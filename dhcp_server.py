from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from controller import Controller
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, dhcp, ipv4, udp


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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if pkt.get_protocol(dhcp.dhcp):
            self.create_dhcp_packet(eth.src, datapath, in_port)

    def create_dhcp_packet(self, dst_mac, dp, port, dst_ip='255.255.255.255'):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,
                                           dst=dst_mac, src=self.DHCP_SERVER_MAC))
        pkt.add_protocol(ipv4.ipv4(dst=dst_ip, src=self.DHCP_SERVER_IP, proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(dhcp.dhcp(op=2, chaddr=dst_mac))
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
