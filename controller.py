from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.app.wsgi import Response
import json
import gzip, zlib
import requests
import ipaddress


class Controller(ControllerBase):
    simple_switch_instance_name = "simple_switch_api_app"
    global scope_net

    def __init__(self, req, link, data, **config):
        super(Controller, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[self.simple_switch_instance_name]

    @route("dhcp_server", "/dashboard", methods=["GET"])
    def evaluate_results(self, req, **kwargs):
        # this is called at the end of the test

        f = open("index.html")
        page = f.read()
        return Response(content_type="text/html", body=page)

    @staticmethod
    def _split(hex_num):
        n = hex_num[2:]
        return [n[i : i + 2] for i in range(0, len(n), 2)]

    def _build(self, hex_num):
        default = ["00", "00", "00", "00"]

        hex_array = self._split(hex_num)
        hex_array.reverse()
        i = -1
        for b in hex_array:
            default[i] = b
            i -= 1
        return [int(x, 16) for x in default]

    @route("dhcp_server", "/data", methods=["POST"])
    def evaluate_dashboard(self, req, **kwargs):
        # this is called at the end of the test
        msg = "Done!"
        scope_netA = req.POST["networkA"]
        scope_netB = req.POST["networkB"]
        scope_netC = req.POST["networkC"]
        gateway = req.POST["gw"]
        dhcp_server = self.simple_switch_app
        dhcp_server.DHCP_SERVER_IP = gateway

        s1 = ipaddress.ip_network(scope_netA)
        s2 = ipaddress.ip_network(scope_netB)
        s3 = ipaddress.ip_network(scope_netC)

        s1_pool = [ip for ip in s1.hosts()]
        s2_pool = [ip for ip in s2.hosts()]
        s3_pool = [ip for ip in s3.hosts()]

        poolstmp = {1: s1_pool, 2: s2_pool, 3: s3_pool}
        dhcp_server.pools = poolstmp
        spacetmp = {1: s1, 2: s2, 3: s3}
        dhcp_server.space = spacetmp

        lease_time = req.POST["time"]

        if int(lease_time) > 4294967295:
            raise Exception

        hex_num = str(hex(int(lease_time)))
        dhcp_server.LEASE_TIME_ACK = self._build(hex_num)

        return msg
