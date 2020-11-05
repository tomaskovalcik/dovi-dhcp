from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.app.wsgi import Response
import json

class Controller(ControllerBase):
    simple_switch_instance_name = 'simple_switch_api_app'

    def __init__(self, req, link, data, **config):
        super(Controller, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[self.simple_switch_instance_name]

    @route('dhcp_server', '/api', methods=['GET'])
    def evaluate_results(self, req, **kwargs):
        # this is called at the end of the test
        msg = 'TEST API ENDPOINT'
        return Response(content_type='application/json', body=json.dumps(msg))
