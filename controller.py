from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.app.wsgi import Response
import json
import gzip,zlib
import requests

class Controller(ControllerBase):
    simple_switch_instance_name = 'simple_switch_api_app'


    def __init__(self, req, link, data, **config):
        super(Controller, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[self.simple_switch_instance_name]

    @route('dhcp_server', '/dashboard', methods=['GET'])
    def evaluate_results(self, req, **kwargs):
        # this is called at the end of the test
        msg = 'TEST API ENDPOINT'
        f = open('index.html')
        page = f.read()
        return Response(content_type='text/html', body=page)

    @route('dhcp_server', '/data', methods=['POST'])
    def evaluate_resul(self, req, **kwargs):
        # this is called at the end of the test
        msg = 'Done!'


        # content=obj_req['Content-Disposition']
        # print(str(content))
        # obj_req=req.headers.get('content-disposition')
        aa = req.POST['network']
        print(aa)
        aa = req.POST['gw']
        print(aa)
        return msg

