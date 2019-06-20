#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: moxie/tests/proxyserver.py
"""
Defines the proxy server used in moxie's test suite.

Classes:
    ProxyServer: Class used to handle proxied requests in the test suite.

Attributes:
    MAX_DATA_RECV (int): Max number of bytes the proxy server receives at once.
    PROXY_PORT_NUMBER (int): Port that the proxy is hosted on.
    SERVER_URL (str): URL the request is made to in order to stop the proxy server.
"""
import socket, requests
from time import sleep

from multiprocessing import Process, Event
from .simpleserver import HOST_NAME, HTTP_PORT_NUMBER

SERVER_URL = 'http://' + HOST_NAME + ':' + str(HTTP_PORT_NUMBER)

PROXY_PORT_NUMBER = 9003

MAX_DATA_RECV = 4096

class ProxyServer:
    """Extremely basic proxy server that simply forwards all traffic along.
    
    http://luugiathuy.com/2011/03/simple-web-proxy-python/ used as a reference

    Methods:
        start(): Start the proxy server subprocess.

        stop(): Cleanly stop the proxy server subprocess.
    """
    def __init__(self):
        self.e = Event() # Event signalling used for stopping the subprocess
        self.server = Process(target=self._run, name='Proxy_Server')
        self.e.set()
        self.sock = None
        attempts = 0
        while(attempts < 5):
            if attempts > 0:
                print(f"Attempting to open socket again in 10 seconds. ({attempts+1}/5)")
                sleep(10)
            try:
                # create the socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # associate the socket to a host and port number
                self.sock.bind(('', PROXY_PORT_NUMBER))
                # release the socket immediately
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # listen for up to 50 connections
                MAX_PENDING_CONNECTIONS = 50
                self.sock.listen(MAX_PENDING_CONNECTIONS)
                break
            except socket.error as e:
                if self.sock:
                    self.sock.close()
                print("Could not open socket: " + str(e))
                attempts += 1

    def start(self):
        """Starts the proxy server."""
        self.server.start()

    def stop(self):
        """Stops the proxy server."""
        self.e.clear()
        requests.get(SERVER_URL, proxies={'http': '127.0.0.1:9003'})
        self.e.set()

    def split_url(self, orig_url):
        """Extracts url and port from a given url."""

        # Default values if not specified in request
        protocol = 'http://'
        path = ''

        # separate the fragment if necessary
        url = orig_url.decode('utf-8')
        url = url.split('#')
        if len(url) > 1:
            url, fragment = url[0], url[1]
        else:
            url, fragment = url[0], None

        # determine the protocol
        url_pos = url.find('://')
        if url_pos != -1:
            temp = url
            protocol = f"{url[:url_pos]}://"
            url = url[url_pos+3:]

        # determine the path, if any
        path_pos = url.find('/')
        if path_pos != -1:
            path = url[path_pos:]
            url = url[:path_pos]
        
        # determine the port, if any
        port_pos = url.find(':')
        if port_pos != -1:
            port = url[port_pos+1:]
            url = url[:port_pos]
       
        return protocol, url, int(port), path

    def _run(self):
        while(self.e.is_set()):
            # Handle requests
            conn, client_addr = self.sock.accept()

            handler = Process(target=self._proxy, name='Request_Handler', args=(conn, client_addr))

            # Since this is only used for testing, we want this to be synchronous.
            handler.start()
            conn.close()

        # Close the socket when we're done.
        self.sock.close()

    def _proxy(self, conn, client_addr):
        # read the request
        request = conn.recv(MAX_DATA_RECV)

        # we need to extract the URL from the first line of the request
        all_lines = request.split(bytes('\n', 'utf-8'))
        first_line = all_lines[0]

        # method is [0], url is [1]
        orig_url = first_line.split(bytes(' ','utf-8'))[1]

        # Split the url into its components.
        protocol, base_url, port, path = self.split_url(orig_url)

        try:
            # Create a socket to connect to the server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((base_url, port))
            s.send(request)

            while True:
                # Receive data from web server
                data = s.recv(MAX_DATA_RECV)
                if len(data) > 0:
                    # send to browser
                    conn.send(data)
                else:
                    break
        except socket.error as e:
            print("Runtime Error: " + str(e))
        finally:
            if s:
                s.close()
            if conn:
                conn.close()        

