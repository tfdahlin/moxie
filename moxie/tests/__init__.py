#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: moxie/tests/__init__.py
"""
Defines the test setup and teardown functions.

Attributes:
    http_server (HTTPServer): Global HTTP server variable used for tests.
    https_server (HTTPServer): Global HTTPS server variable used for tests.
    proxy_server (ProxyServer): Global proxy server variable used for tests
"""

import json, requests, ssl, os, base64, socket

from .simpleserver import SimpleServer, SERVER_URL, HTTPS_SERVER_URL
from .proxyserver import ProxyServer

from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing import Process, Event
from requests_toolbelt.multipart import decoder
from threading import Thread
from urllib.parse import unquote

"""
str: Host loopback address.

For some reason, using 'localhost' causes some issues when stopping and starting
the server. Using the loopback address fixes this.
"""

http_server = None

https_server = None

proxy_server = None
        
def setup_package():
    """Setup HTTP and HTTPS servers for tests."""
    global http_server
    http_server = SimpleServer()
    http_server.start()

    global https_server
    https_server = SimpleServer(use_ssl=True)
    https_server.start()

    global proxy_server
    proxy_server = ProxyServer()
    proxy_server.start()

def teardown_package():
    """Teardown HTTP and HTTPS servers for tests."""
    # We need to tear down the proxy server first because it relies on the other servers to shut down
    global proxy_server
    proxy_server.stop()

    global http_server
    http_server.stop()

    global https_server
    https_server.stop()


if __name__ == "__main__":
    pass
