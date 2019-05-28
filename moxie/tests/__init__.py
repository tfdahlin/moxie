#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Allows for the creation of a simple HTTP server.

Classes:
    SimpleHTTPServerRequestHandler: Subclass of BaseHTTPRequestHandler for user with the SimpleServer object.

    SimpleServer: Wrapper for the http.server HTTPServer class

Attributes:
    HOST_NAME (str): Hostname used for creating SERVER_URL.
    HTTP_PORT_NUMBER (int): Port number for HTTP server creation.
    HTTPS_PORT_NUMBER (int): Port number for HTTPS server creation.
    SERVER_URL (str): URL passed to Session object for running tests.
    HTTPS_SERVER_URL (str): URL passed to Session object for running https tests.
    http_server (HTTPServer): Global HTTP server variable used for tests.
    https_server (HTTPServer): Global HTTPS server variable used for tests.
"""

import json, requests, ssl, os, base64

from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing import Process, Event
from requests_toolbelt.multipart import decoder
from threading import Thread
from urllib.parse import unquote

HOST_IP = '127.0.0.1'
"""
str: Host loopback address.

For some reason, using 'localhost' causes some issues when stopping and starting
the server. Using the loopback address fixes this.
"""

HOST_NAME = 'localhost'

HTTP_PORT_NUMBER = 9001

HTTPS_PORT_NUMBER = 9002

SERVER_URL = 'http://' + HOST_NAME + ':' + str(HTTP_PORT_NUMBER)

HTTPS_SERVER_URL = 'https://' + HOST_NAME + ':' + str(HTTPS_PORT_NUMBER)

http_server = None

https_server = None

# HTTPRequestHandler class
class SimpleHTTPServerRequestHandler(BaseHTTPRequestHandler):
    """BaseHTTPRequestHandler subclass for handling HTTP requests."""

    def _parse_multipart(self, raw, delimiter):
        """Parse multipart/form-data requests into a dict"""

        # Split on delimiter
        split = raw.split(bytes('--'+delimiter, 'utf-8'))
        # Get rid of the empty bits
        split = list(filter(lambda x: len(x) > 0, split))
        # Remove whitespace on either end, convert to strings from bytes
        #  and remove the final element which is a trailing '--' from the split
        split = list(map(lambda x: x.strip().decode('utf-8'), split))[:-1]
        my_dict = {}
        for element in split:
            # The first \r\n\r\n pattern delineates key from value, so split
            #  on this and work with the first element for the keyname
            tmp = element.split('\r\n\r\n')
            # Split key at semicolon
            k = list(map(lambda x: x.strip(),tmp[0].split(';')))
            # Find the element that starts with 'name' --
            #  this looks something like: 'name="foo"'
            k = list(filter(lambda x: x.startswith('name'),k))[0]
            # Now that we have the name mapping, split on '=' and
            #  strip the quotation marks from the value
            k = k.split('=')[1][1:-1]
            # Since we split on \r\n\r\n, we need to rejoin if necessary
            #  for the remainder of tmp
            v = '\r\n\r\n'.join(tmp[1:])
            my_dict[k] = v
        return my_dict

    def _dictify_request(self):
        """Attempt to read the content of the request and turn it into a dict."""
        content_length = int(self.headers['Content-Length'])
        content = self.rfile.read(content_length)
        content_type = self.headers['Content-Type']
        result = {}
        success = False # fallback to returning failure
        # attempt to load as json if it's described as such
        if(content_type == 'application/json'):
            try:
                result = json.loads(content)
                success = True
            except Exception as e:
                print(e)
        # attempt to load form-urlencoded data if it's described as such
        elif(content_type == 'application/x-www-form-urlencoded'):
            try:
                stringified = content.decode()
                k_v = stringified.split('&')
                k_v = list(map(lambda x: x.split('='), k_v))
                result = {unquote(a[0]): unquote(a[1]) for a in k_v}
                success = True
            except Exception as e:
                print(e)
        # attempt to load as form-data if it's described as such
        elif('multipart/form-data' in content_type):
            delimiter = content_type.split('=')[1]
            try:
                result = self._parse_multipart(content, delimiter)
                success = True
            except Exception as e:
                print(e)
        else:
            # Unknown content-type -- assume json by default
            try: # data is already json format
                data = json.loads(content)
                success = True
            except Exception as e:
                print("ERROR PARSING DATA -- UNKNOWN CONTENT-TYPE")
                print(e)
                print(content)
                print(self.headers)
        return result, success


    def _set_headers(self, code=200, content_type='application/json', headers=None, update_cookie=True):
        """Set the headers for a response."""
        self.send_response(code)
        self.send_header('Content-type', content_type)
        current_cookie = self.headers['Cookie']
        # Process and update cookies with a 'step' cookie.
        # This allows us to test whether cookies are stored properly or not.
        if update_cookie:
            if not current_cookie: # Create the cookie if it doesn't exist
                self.send_header('Set-Cookie', 'step=1')
            else: # Increment it as necessary
                all_cookies = current_cookie.split('&')
                step_cookie = list(filter(lambda x: x.split('=')[0]=='step',all_cookies))
                all_cookies = list(filter(lambda x: x.split('=')[0]!='step', all_cookies))
                if len(step_cookie) == 1:
                    step_cookie = 'step=' + str(int(step_cookie[0].split('=')[1])+1)
                else:
                    step_cookie = 'step=1'

                all_cookies.append(step_cookie)
                all_cookies = '&'.join(all_cookies)
                self.send_header('Set-Cookie', all_cookies)
        else:
            print("NOT UPDATING COOKIE")
        if headers:
            for header, header_value in headers.items():
                self.send_header(header, header_value)
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/404': # special 404 route
            self._set_headers(code=404, headers={'X-TEST-REQUEST_TYPE': 'GET'})
            return
        if self.path == '/redirect': # special redirect route
            self._set_headers(code=301, headers={'Location': 'http://' + self.address_string() + ':' + str(self.connection.getsockname()[1]) + '/'})
            return
        if self.path == '/non-json': # special route that returns non-json
            self._set_headers(content_type='text/html',headers={'X-TEST-REQUEST_TYPE': 'GET'})
            self.wfile.write(bytes(''.join([
            '<!DOCTYPE html>',
            '<html>',
                '<head>',
                    '<title>Website title.</title>',
                '</head>',
                '<body>',
                    'Webpage body.',
                '</body>',
            '</html>'])
            , 'UTF-8'))
            return
        if self.path == '/no-update-cookie':
            self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'GET'}, update_cookie=False)
            self.wfile.write(bytes(json.dumps({'success': True, 'request_type': 'GET'}), 'UTF-8'))
            return
        if self.path.startswith('/check-auth/'):
            # Extract the username/password from the url
            auth_string = self.path[12:]
            auth_user = auth_string.split(':')[0]
            auth_pass = auth_string.split(':')[1]
           
            # Assert that the authorizaiton header exists 
            if not self.headers['Authorization']:
                raise Exception('Basic auth missing.')

            basic_auth = self.headers['Authorization'].split()[1]
            if base64.b64encode(bytes(auth_string, 'UTF-8')) != bytes(basic_auth, 'UTF-8'):
                self._set_headers(code=500, headers={'X-TEST-REQUEST_TYPE': 'GET'})
                self.wfile.write(bytes(json.dumps({'success': False}), 'UTF-8'))
                return
            self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'GET'})
            self.wfile.write(bytes(json.dumps({'success': True}), 'UTF-8'))
            return
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'GET'})
        self.wfile.write(bytes(json.dumps({'success': True}), 'UTF-8'))
        return

    def do_OPTIONS(self):
        """Handle OPTIONS requests."""
        # All we care about is setting the correct headers -- no content
        self._set_headers(headers={
            'X-TEST-REQUEST_TYPE': 'OPTIONS', 
            'Access-Control-Allow-Origin': self.headers['origin'],
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE, HEAD'
        })
        return

    def do_POST(self):
        """Handle POST requests."""
        # Because this is only used for testing, we don't care much about
        #  the contents, so we simply repeat it back in the response.
        content, success = self._dictify_request()
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'POST'})
        self.wfile.write(bytes(json.dumps({'success': success, 'data': content}), 'UTF-8'))
        return

    def do_PUT(self):
        """Handle PUT requests."""
        # Because this is only used for testing, we don't care much about
        #  the contents, so we simply repeat it back in the response.
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'PUT'})
        content, success = self._dictify_request()
        self.wfile.write(bytes(json.dumps({'success': success, 'data': content}), 'UTF-8'))
        return

    def do_DELETE(self):
        """Handle DELETE requests."""
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'DELETE'})
        self.wfile.write(bytes(json.dumps({'success': True}), 'UTF-8'))
        return
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'HEAD'})
        return

    def log_message(self, format, *args):
        """Override default logging
        
        Use almost the same behavior, but log to stdout instead of stderr so that nose will capture the output when running tests.
        """
        debug = True
        if debug:
            print(f"{self.address_string()} - - [{self.log_date_time_string()}] {format%args}\n")
        else:
            super(SimpleHTTPServerRequestHandler, self).log_message(format, *args)
        

class SimpleServer:
    """Wrapper object for the http.server HTTPServer object.

    This wrapper allows a simple HTTP server to be started and stopped as a subprocess without any hassle to make testing easier.

    Methods:
        start(): Start the HTTP server subprocess.

        stop(): Cleanly stop the HTTP server subprocess.
    """
    def __init__(self, use_ssl=False):
        self.e = Event() # Event signalling used for stopping the subprocess
        self.server = Process(target=self._run, args=[use_ssl])
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
            pass # Sometimes we can't make the request?
        # Then we wait for the server process to exit, and create
        #  a new subprocess to start if we need it.
        self.server.join()
        self.server = Process(target=self._run)
        self.e.set()

    # Method used for the server subprocess
    def _run(self, use_ssl):
        not_running = True
        # We start with port 9001, and increment until we find an available port
        while not_running:
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
                    curr_path = os.path.abspath(__file__)[:-11]
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

def setup_package():
    """Setup HTTP and HTTPS servers for tests."""
    global http_server
    http_server = SimpleServer()
    http_server.start()

    global https_server
    https_server = SimpleServer(use_ssl=True)
    https_server.start()

def teardown_package():
    """Teardown HTTP and HTTPS servers for tests."""
    global http_server
    http_server.stop()
    global https_server
    https_server.stop()

if __name__ == "__main__":
    pass
