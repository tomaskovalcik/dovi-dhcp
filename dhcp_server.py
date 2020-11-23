from ryu.app import simple_switch_13
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from controller import Controller
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, dhcp, ipv4, udp, arp, ether_types
from ryu.lib import addrconv
import ipaddress
from ryu.ofproto import inet


class DhcpServer(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    DHCP_SERVER_MAC = "aa:bb:cc:dd:ee:ff"
    DHCP_SERVER_IP = None
    scope1 = "192.168.1.0/29"
    s1 = ipaddress.ip_network(scope1)
    s2 = ipaddress.ip_network("192.168.1.8/29")
    s3 = ipaddress.ip_network("192.168.1.16/29")
    LEASE_TIME_ACK = b"\xFF\xFF\xFF\xFF"

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
            7: "DHCP RELEASE",
        }
        self.database = {}
        self.temp_offered = {}

        self.s1_pool = [ip for ip in self.s1.hosts()]
        self.s2_pool = [ip for ip in self.s2.hosts()]
        self.s3_pool = [ip for ip in self.s3.hosts()]

        self.pools = {1: self.s1_pool, 2: self.s2_pool, 3: self.s3_pool}
        self.space = {1: self.s1, 2: self.s2, 3: self.s3}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if self.DHCP_SERVER_IP is None:
            return

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dhcp_packet = pkt.get_protocol(dhcp.dhcp)

        if (
            eth.ethertype == ether_types.ETH_TYPE_ARP
            and pkt.get_protocol(arp.arp).dst_ip == self.DHCP_SERVER_IP
        ):
            self.create_arp_packet(
                pkt.get_protocol(arp.arp).src_ip, eth.src, in_port, datapath
            )
            return

        self.add_flow_erase_dup(datapath)

        if not dhcp_packet:
            super(DhcpServer, self)._packet_in_handler(ev)
        else:
            msg_type = ord(dhcp_packet.options.option_list[0].value)
            if self.messages.get(msg_type) == "DHCP DISCOVER":
                self.create_dhcp_offer(dhcp_packet, datapath, in_port)
            elif self.messages.get(msg_type) == "DHCP REQUEST":
                self.create_dhcp_ack(dhcp_packet, datapath, in_port)
            elif self.messages.get(msg_type) == "DHCP RELEASE":
                self.handle_dhcp_release(dhcp_packet, datapath)

    def handle_dhcp_release(self, dhcp_packet, dp):
        client_id = dhcp_packet.chaddr
        released_ip = self.database.get(client_id)

        # released ip address is inserted at the beginning
        # of the pool, so the next lookup is little bit faster
        if released_ip:
            self.pools[dp.id].insert(0, released_ip)

    def add_flow_erase_dup(self, dp):
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

    def _ip_to_int(self):
        dhcp_server_ip = self.DHCP_SERVER_IP.split(".")
        return [int(x) for x in dhcp_server_ip]

    def create_dhcp_ack(self, dhcp_packet, dp, port, dst_ip="255.255.255.255"):

        if self.temp_offered.get(dhcp_packet.xid) is None:
            return

        subnet_mask = self.space[dp.id].netmask
        yiaddr = self.temp_offered[dhcp_packet.xid]["yiaddr"]
        chaddr = self.temp_offered[dhcp_packet.xid]["chaddr"]

        # add new or update existing dhcp bindings
        # we remember only last used ip address
        self.database[chaddr] = yiaddr

        pkt = packet.Packet()
        dhcp_ack_msg_type = b"\x05"
        subnet_option = dhcp.option(
            tag=dhcp.DHCP_SUBNET_MASK_OPT,
            value=addrconv.ipv4.text_to_bin(subnet_mask),
        )

        time_option = dhcp.option(
            tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT, value=bytearray(self.LEASE_TIME_ACK)
        )
        msg_option = dhcp.option(
            tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=dhcp_ack_msg_type
        )

        dhcp_server_option = dhcp.option(
            tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=bytearray(self._ip_to_int())
        )

        options = dhcp.options(
            option_list=[
                msg_option,
                time_option,
                subnet_option,
                dhcp_server_option,
            ]
        )

        hlen = dhcp_packet.hlen
        dhcp_pkt = dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            hlen=hlen,
            chaddr=dhcp_packet.chaddr,
            yiaddr=yiaddr,
            siaddr=self.DHCP_SERVER_IP,
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
        yiaddr = None

        previous_ip = self.database.get(chaddr)

        if previous_ip:
            if previous_ip in self.pools[dp.id]:
                self.pools[dp.id].remove(previous_ip)
                yiaddr = previous_ip
            else:
                yiaddr = self.pools[dp.id].pop(-1)
        else:
            yiaddr = self.pools[dp.id].pop(-1)

        self.temp_offered[xid] = {"chaddr": chaddr, "yiaddr": yiaddr}

        pkt = packet.Packet()
        dhcp_offer_msg_type = b"\x02"
        hlen = dhcp_packet.hlen

        msg_option = dhcp.option(
            tag=dhcp.DHCP_MESSAGE_TYPE_OPT, value=dhcp_offer_msg_type
        )

        dhcp_server_option = dhcp.option(
            tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT, value=bytearray(self._ip_to_int())
        )
        options = dhcp.options(option_list=[msg_option, dhcp_server_option])

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
                siaddr=self.DHCP_SERVER_IP,
                xid=dhcp_packet.xid,
                giaddr=dhcp_packet.giaddr,
                chaddr=chaddr,
                options=options,
            )
        )
        pkt.serialize()
        self.inject_packet(pkt, dp, port)

    def create_arp_packet(self, dst_ip, dst_mac, src_port=None, datapath=None):
        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                dst=dst_mac,
                src=self.DHCP_SERVER_MAC,
                ethertype=ether.ETH_TYPE_ARP,
            )
        )
        pkt.add_protocol(
            arp.arp(
                hwtype=1,
                proto=0x0800,
                hlen=6,
                plen=4,
                opcode=2,
                src_mac=self.DHCP_SERVER_MAC,
                src_ip=self.DHCP_SERVER_IP,
                dst_mac=dst_mac,
                dst_ip=dst_ip,
            )
        )
        pkt.serialize()
        self.inject_packet(pkt, datapath, src_port)

    @staticmethod
    def inject_packet(pkt, dp, port):
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
