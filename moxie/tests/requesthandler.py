#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: moxie/tests/requesthandler.py
"""
Defines the class that handles requests to a basic HTTP server.

Classes:
    SimpleHTTPServerRequestHandler: Subclass of BaseHTTPRequestHandler for use with the SimpleServer object.

Attributes:
    toggle (bool): Toggle used for changing functionality between calls in the http server.
"""

import json, base64

from http.server import BaseHTTPRequestHandler
from urllib.parse import unquote

toggle = None

class SimpleHTTPServerRequestHandler(BaseHTTPRequestHandler):
    """BaseHTTPRequestHandler subclass for handling HTTP requests."""
    def __init__(self, *args, **kwargs):
        #self.toggle = None
        super().__init__(*args, **kwargs)

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
            pass
            #print("NOT UPDATING COOKIE")
        if headers:
            for header, header_value in headers.items():
                self.send_header(header, header_value)
        self.end_headers()
    
    def return_non_json(self):
        """Return a non-json response."""
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

    def check_auth(self):
        """Check basic auth request."""

        # Extract the username/password from the url
        auth_string = self.path[12:]
        auth_user = auth_string.split(':')[0]
        auth_pass = auth_string.split(':')[1]
       
        # Assert that the authorizaiton header exists 
        if not self.headers['Authorization']:
            raise Exception('Basic auth missing.')

        # Should be formatted as 'Basic <b64 encoded authstring>'
        basic_auth = self.headers['Authorization'].split()[1]
        # Mismatch means failue
        if base64.b64encode(bytes(auth_string, 'UTF-8')) != bytes(basic_auth, 'UTF-8'):
            self._set_headers(code=500, headers={'X-TEST-REQUEST_TYPE': 'GET'})
            self.wfile.write(bytes(json.dumps({'success': False}), 'UTF-8'))
            return
        # Otherwise return success.
        self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'GET'})
        self.wfile.write(bytes(json.dumps({'success': True}), 'UTF-8'))
        return

    def process_cache(self):
        """Handle cache requests."""
        global toggle

        # Extract the remainder of the path string
        subpath = self.path[7:]
        cache_controls = []
        response_code = 200
        etag = 'thisismyetag'
        # GET /cache/no-store
        if 'no-store' in subpath:
            cache_controls.append('No-Store')
        elif 'no-cache' in subpath:
            cache_controls.append('No-Cache')
            # GET /cache/no-cache/mismatch
            if 'mismatch' in subpath:
                # Switch between the two etags
                if toggle:
                    etag = 'mismatchedtag'
                    toggle = None
                else:
                    etag = 'thesedontmatch'
                    toggle = True
            else:
                # If we aren't asking for a mismatch, check if the tag is passed
                if 'If-None-Match' in self.headers:
                    if self.headers['If-None-Match'] == 'thisismyetag':
                        response_code = 304
            
            # If max-age is to be passed
            if 'no-max-age' not in subpath:
                # GET /cache/no-cache/short
                if 'short' in subpath:
                    cache_controls.append('max-age=1')
                # GET /cache/no-cache
                else:
                    cache_controls.append('max-age=1200')
            else:
                # GET /cache/no-cache/no-max-age
                # If max-age isn't supposed to be passed
                if toggle:
                    toggle = None
                else:
                    cache_controls.append('max-age=3')
                    toggle = True
                
            if 'no-etag' in subpath:
                if toggle:
                    etag = None
                    toggle = None
                else:
                    etag = 'thisismyetag'
                    toggle = True
        elif 'empty' in subpath:
            cache_controls.append('')
            pass
        else:
            if 'If-None-Match' in self.headers:
                if self.headers['If-None-Match'] == 'thisismyetag':
                    response_code = 304
            if 'no-max-age' not in subpath:
                cache_controls.append('max-age=1200')
            else:
                cache_controls.append('Public')
        cache_control_string = ', '.join(cache_controls)
        res_headers = {
            'X-TEST-REQUEST_TYPE': 'GET',
            'Cache-Control': cache_control_string,
        }
        if etag:
            res_headers['ETag'] = etag
        self._set_headers(code=response_code, headers=res_headers)
        self.wfile.write(bytes(json.dumps({'success': True}), 'UTF-8'))
        return
        

    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/404': # special 404 route
            self._set_headers(code=404, headers={'X-TEST-REQUEST_TYPE': 'GET'})
            return
        if self.path == '/redirect': # special redirect route
            self._set_headers(code=301, headers={'Location': 'http://' + self.address_string() + ':' + str(self.connection.getsockname()[1]) + '/'})
            return
        if self.path == '/non-json': # special route that returns non-json
            self.return_non_json()
            return
        if self.path == '/no-update-cookie':
            self._set_headers(headers={'X-TEST-REQUEST_TYPE': 'GET'}, update_cookie=False)
            self.wfile.write(bytes(json.dumps({'success': True, 'request_type': 'GET'}), 'UTF-8'))
            return
        if self.path.startswith('/check-auth/'):
            self.check_auth()
            return
        if self.path.startswith('/cache/'):
            self.process_cache()
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
        silent = False
        if silent:
            return
        if debug:
            print(f"{self.address_string()} - - [{self.log_date_time_string()}] {format%args}\n")
        else:
            super(SimpleHTTPServerRequestHandler, self).log_message(format, *args)
        
