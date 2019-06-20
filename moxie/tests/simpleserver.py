#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: moxie/tests/simpleserver.py
"""
Defines the class that instantiates a basic http server.

Classes:
    SimpleServer: Wrapper object for the HTTPServer object.

Attributes:
    HOST_NAME (str): Hostname used for creating SERVER_URL elsewhere.
    HOST_IP (str): IP address used for defining the server address.
    HTTP_PORT_NUMBER (int): Port number used for HTTP server creation.
    HTTPS_PORT_NUMBER (int): Port number used for HTTPS server creation.
    SERVER_URL (str): Base HTTP url used for tests.
    HTTPS_SERVER_URL (str): Base HTTPS url used for tests.
"""

import os, ssl, requests
from multiprocessing import Event, Process
from http.server import HTTPServer

from .requesthandler import SimpleHTTPServerRequestHandler

HOST_NAME = 'localhost'
HOST_IP = '127.0.0.1'
HTTP_PORT_NUMBER = 9001
HTTPS_PORT_NUMBER = 9002
SERVER_URL = f'http://{HOST_NAME}:{HTTP_PORT_NUMBER}'
HTTPS_SERVER_URL = f'https://{HOST_NAME}:{HTTPS_PORT_NUMBER}'


class SimpleServer:
    """Wrapper object for the http.server HTTPServer object.

    This wrapper allows a simple HTTP server to be started and stopped as a subprocess without any hassle to make testing easier.

    Methods:
        start(): Start the HTTP server subprocess.

        stop(): Cleanly stop the HTTP server subprocess.
    """
    def __init__(self, use_ssl=False):
        self.e = Event() # Event signalling used for stopping the subprocess
        self.server = Process(target=self._run, name='Server_Process', args=[use_ssl])
        self.e.set()
        self.use_ssl = use_ssl

    def start(self):
        """Starts the HTTP webserver"""
        self.server.start()

    def stop(self):
        """Stops the HTTP webserver"""
        self.e.clear()
        if self.use_ssl:
            # We need to disable warnings because of self-signing
            requests.packages.urllib3.disable_warnings()
        # We need to fake a get request to the server in order for it
        #  to exit, because it will hang until the next request is made.
        try: # Make a request to the right URL
            if self.use_ssl:
                requests.get(HTTPS_SERVER_URL, verify=False)
            else:
                requests.get(SERVER_URL, verify=False)
        except Exception as e:
            print("Exception while attempting to handle stop request:")
            raise e
        # Then we wait for the server process to exit, and create
        #  a new subprocess to start if we need it.
        self.server.join()
        self.server = Process(target=self._run, name='Server_Process', args=[self.use_ssl])
        self.e.set()

    # Method used for the server subprocess
    def _run(self, use_ssl):
        # For SOME reason, using 'localhost' instead of '127.0.0.1'
        #  causes an OSError about the address already being in use when
        #  multiple servers are started and stopped consecutively. Google
        #  searches reveal this is related to a WAIT_TIME for a socket. 
        #  Although this wait time can be overridden to allow the port to
        #  be reopened immediately, it cannot be used to reconnect to the
        #  host on the same port, which seems to be the cause of this issue.
        #  This is theoretically fixed by the setup and teardown functions
        #  that only spawn a single server, but I'm leaving HOST_IP instead
        #  of using 'localhost' because it worked better before implementing
        #  this solution.
        if use_ssl:
            server_address = (HOST_IP, HTTPS_PORT_NUMBER)
        else:
            server_address = (HOST_IP, HTTP_PORT_NUMBER)
        try:
            httpd = HTTPServer(server_address, SimpleHTTPServerRequestHandler)
            # set up ssl on the socket if necessary
            if use_ssl:
                # the key and cert files must be in the same folder as
                # this file.
                curr_path = os.path.abspath(__file__)[:-15]
                httpd.socket = ssl.wrap_socket(httpd.socket,
                    keyfile=curr_path + 'key.pem',
                    certfile=curr_path + 'cert.pem',
                    server_side=True)
            not_running = False
        except ConnectionError:
            print(f"Port {port} already in use")
            return
        # Handle requests as they come in. handle_request() is a blocking method,
        #  so we need to make a fake request to the server to get it to actually
        #  exit after we clear e.
        while self.e.is_set():
            httpd.handle_request()
        # Close the server nicely.
        httpd.server_close()
        print("Server closed.")
