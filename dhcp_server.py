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
import ipaddress
from ryu.ofproto import inet

# TODO: databaza pre alokovane IP
# TODO: pridat pravidla pre switche - aby nechodili duplikaty
# TODO: ak client uvolni IP adresu, naspat ju pridat do poolu
# TODO: ak client uz raz dostal IP adresu, tak snazit sa pridat tu istu adresu zase
# TODO: riadit sa https://tools.ietf.org/html/rfc2131#section-4.1 a minimalne spravit veci co su opisane v sekcii 3.1 a 3.2


class DhcpServer(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    # TODO: najst lepsi sposob ako toto robit, nepaci sa mi to velmi
    DHCP_SERVER_MAC = "aa:bb:cc:dd:ee:ff"
    DHCP_SERVER_IP=None
    scope1="192.168.1.0/29"
    s1 = ipaddress.ip_network(scope1)
    s2 = ipaddress.ip_network("192.168.1.8/29")
    s3 = ipaddress.ip_network("192.168.1.16/29")

    def __init__(self, *args, **kwargs):
        super(DhcpServer, self).__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]
        wsgi.register(Controller, {Controller.simple_switch_instance_name: self})
        self.dup = []
        self.messages = {
            1: "DHCP DISCOVER",
            2: "DHCP OFFER",
            3: "DHCP REQUEST",
            4: "DHCP ACK",
        }

        # TODO: premysliet databazu, neviem ci jednoduchy dict bude stacit..
        self.database = {}
        self.dp = {}
        # toto predstavuje temp databazu - teda zatial tam ukladam IP adresy ktore su v procese pridelovania
        # neviem aky to ma zmysel zatial to necham tak
        self.temp_offered = {}

        self.s1_pool = [ip for ip in self.s1.hosts()]
        self.s2_pool = [ip for ip in self.s2.hosts()]
        self.s3_pool = [ip for ip in self.s3.hosts()]

        self.pools = {1: self.s1_pool, 2: self.s2_pool, 3: self.s3_pool}
        self.space = {1: self.s1, 2: self.s2, 3: self.s3}

    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in(self, ev):
    #     msg = ev.msg
    #     datapath = msg.datapath
    #     in_port = msg.match["in_port"]
    #     # self.dp[str(datapath.id)]=datapath
    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocols(ethernet.ethernet)[0]
    #     dhcp_packet = pkt.get_protocol(dhcp.dhcp)
    #
    #     if dhcp_packet:

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        dhcp_packet = pkt.get_protocol(dhcp.dhcp)

        self.add_flow_erase_dup(datapath, in_port, dhcp_packet)

        if not dhcp_packet:
            super(DhcpServer, self)._packet_in_handler(ev)
        else:
            msg_type = ord(dhcp_packet.options.option_list[0].value)
            if self.messages.get(msg_type) == "DHCP DISCOVER":
                self.create_dhcp_offer(dhcp_packet, datapath, in_port)
            elif self.messages.get(msg_type) == "DHCP REQUEST":
                self.create_dhcp_ack(dhcp_packet, datapath, in_port)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    def add_flow_erase_dup(self, dp, in_port, dhcppkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]

        match = parser.OFPMatch(
            # in_port=in_port,
            eth_type=ether.ETH_TYPE_IP,
            eth_dst="ff:ff:ff:ff:ff:ff",
            ip_proto=inet.IPPROTO_UDP,
            ipv4_src="0.0.0.0",
            ipv4_dst="255.255.255.255",
            udp_src=68,
            udp_dst=67,
        )

        self.add_flow(dp, 10, match, actions)

    def create_dhcp_ack(self, dhcp_packet, dp, port, dst_ip="255.255.255.255"):

        if self.temp_offered.get(dhcp_packet.xid) is None:
            return

        subnet_mask = self.space[dp.id].netmask
        yiaddr = self.temp_offered[dhcp_packet.xid]["yiaddr"]
        chaddr = self.temp_offered[dhcp_packet.xid]["chaddr"]

        pkt = packet.Packet()
        dhcp_ack_msg_type = b"\x05"
        subnet_option = dhcp.option(
            tag=dhcp.DHCP_SUBNET_MASK_OPT,
            value=addrconv.ipv4.text_to_bin(subnet_mask),
        )
        time_option = dhcp.option(
            tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=b"\xFF\xFF\xFF\xFF"
        )
        msg_option = dhcp.option(
            tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=dhcp_ack_msg_type
        )
        options = dhcp.options(
            option_list=[
                msg_option,
                time_option,
                subnet_option,
            ]
        )

        hlen = dhcp_packet.hlen
        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            hlen=hlen,
            chaddr=dhcp_packet.chaddr,
            yiaddr=yiaddr,
            giaddr=dhcp_packet.giaddr,
            xid=dhcp_packet.xid,
            options=options,
        )

        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_IP, dst=chaddr, src=self.DHCP_SERVER_MAC
            )
        )
        pkt.add_protocol(ipv4.ipv4(dst=dst_ip, src=self.DHCP_SERVER_IP, proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(dhcp_pkt)
        pkt.serialize()

        self.inject_packet(pkt, dp, port)

    def create_dhcp_offer(self, dhcp_packet, dp, port, dst_ip="255.255.255.255"):
        xid = dhcp_packet.xid  # transaction id
        chaddr = dhcp_packet.chaddr
        yiaddr = self.pools[dp.id].pop(-1)
        self.temp_offered[xid] = {"chaddr": chaddr, "yiaddr": yiaddr}

        # for i in self.dup:
        #     if i == xid:
        #         return

        pkt = packet.Packet()
        dhcp_offer_msg_type = b"\x02"
        hlen = dhcp_packet.hlen

        msg_option = dhcp.option(
            tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=dhcp_offer_msg_type
        )
        options = dhcp.options(option_list=[msg_option])

        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_IP, dst=chaddr, src=self.DHCP_SERVER_MAC
            )
        )

        pkt.add_protocol(ipv4.ipv4(dst=dst_ip, src=self.DHCP_SERVER_IP, proto=17))
        pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        pkt.add_protocol(
            dhcp.dhcp(
                hlen=hlen,
                op=dhcp.DHCP_BOOT_REPLY,
                yiaddr=yiaddr,
                xid=dhcp_packet.xid,
                giaddr=dhcp_packet.giaddr,
                chaddr=chaddr,
                options=options,
            )
        )
        pkt.serialize()
        # self.dup.append(xid)
        self.inject_packet(pkt, dp, port)

    def inject_packet(self, pkt, dp, port):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        data = pkt.data
        action = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action,
            data=data,
        )
        dp.send_msg(out)
