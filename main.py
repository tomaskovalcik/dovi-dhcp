#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from ryu.cmd import manager


def start_controller():

    sys.argv.append("--observe-links")
    sys.argv.append("--ofp-tcp-listen-port")
    sys.argv.append("3939")
    sys.argv.append("dhcp_server")
    sys.argv.append("--enable-debugger")

    manager.main()


if __name__ == "__main__":
    start_controller()
