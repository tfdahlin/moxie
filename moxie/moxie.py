#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simplifies user interactions with web applications.

The requests library (https://python-requests.org/) is a great tool for performing web requests, but debugging requests isn't easy.
In order to print out more details about a request, such as the exact content of the body, a lot of hoops need to be jumped through with the Python Requests library. To do this, a Request object must be made, then prepared, then sent with a Session object. The entirety of the request can be seen when the request object is made, but simply calling requests.verb() or Session.verb() does not allow for inspection.
The goal of this module is to provide functionality that more closely resembles that of a web client, to make automated interactions simpler, and to make debugging easier. It accomplishes this by allowing users to create stateful objects that automatically track and update cookies as necessary, and by providing methods that allow the user to easily customize output levels of request and response information.

Classes:
    Session:

Exceptions:
    OptionDoesNotExist:
"""

import requests, json, urllib.parse, re, warnings
import urllib3
from urllib.parse import unquote, quote

class OptionDoesNotExist(KeyError):
    """Use when an invalid output option is provided.

    Args:
        msg (str): Human-readable string describing the exception.

    Attributes:
        msg (str): Human-readable string describing the exception.
    """

    def __init__(self, msg):
        self.msg = msg

class Session():
    """Client-like object for simplifying web application interactions.

    Args:
        base_url (str): The base url to be used by the session object. If a
            base url is not specified, then all requests should provide the
            full url path. If a base url is specified, relative paths may be
            used for requests instead.

    Attributes:
        url (str): The base url for the website being visited, if specified.
        cookies (CookieJar): The cookies associated with the current session.
        prettify_json (bool): Indicates whether to prettify the json output.
        json_output (bool): Indicates if output should be interpreted as json.
        raise_status (bool): Raises an exception for response codes greater than 400.
    """
    def __init__(self, base_url=None, auth_user=None, auth_pass=None, auth_type=None):
        self._url = base_url
        self.req_output_options = {}
        """req_output_options (dict): Output options for requests. 
                Describes what parts of a request should be printed.
        """
        self.res_output_options = {}
        """rew_output_options (dict): Output options for responses.
                Describes what parts of a response should be printed.
        """
        self._cookies = requests.cookies.RequestsCookieJar()
        self._proxy = {}
        self._req = None
        self._res = None
        self._user = auth_user
        self._pass = auth_pass
        self._session = None
        if auth_user or auth_pass:
            self._auth = requests.auth.HTTPBasicAuth(auth_user, auth_pass)
        else:
            self._auth = None
        self._user_agent = 'Moxie Agent'
        
        # Default settings for a new object:
        # - Exceptions are not raised for status codes >= 400.
        # - Output will attempt to interpret as json, and pretty-print it.
        # - Requests URL and method are printed.
        # - Response codes are printed.
        # - SSL warnings are disabled.
        # - SSL verification is disabled.

        # These decisions were made because this library is assumed to be used
        #  in a development or testing environment, and not all information is
        #  needed all the time.
        self.disable_raise_for_status()
        self.enable_json_output()
        self.enable_pretty_json()
        self.set_default_request_output_options()
        self.set_default_response_output_options()
        self.disable_warnings()
        self.disable_verification()
        self.disable_proxy()

    def get(self, path, **kwargs):
        """Wrapper for requests.get().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.get() method.

        Returns:
            Response object from requests library.
        """
        return self._request('GET', path, **kwargs)

    def post(self, path, **kwargs):
        """Wrapper for requests.post().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.post() method.

        Returns:
            Response object from requests library.
        """
        return self._request('POST', path, **kwargs)

    def options(self, path, **kwargs):
        """Wrapper for requests.options().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.options() method.

        Returns:
            Response object from requests library.
        """
        return self._request('OPTIONS', path, **kwargs)

    def put(self, path, **kwargs):
        """Wrapper for requests.put().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.put() method.

        Returns:
            Response object from requests library.
        """
        return self._request('PUT', path, **kwargs)

    def delete(self, path, **kwargs):
        """Wrapper for requests.delete().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.delete() method.

        Returns:
            Response object from requests library.
        """
        return self._request('DELETE', path, **kwargs)

    def head(self, path, **kwargs):
        """Wrapper for requests.head().
        
        Args:
            path (str): The path the request is being made to.
                If a base url is used when creating the Session object, then
                the path will be appended to the base url. For example, if the
                base url is "https://example.com", and the path is "/my_path",
                then a request will be made to "https://example.com/"

            **kwargs: Additional arguments to be passed to the requests.head() method.

        Returns:
            Response object from requests library.
        """
        return self._request('HEAD', path, **kwargs)

    def _request(self, req_type, path, **kwargs):
        """Private method for preparing and sending requests.
        
        Args:
            req_type (str): The type of request to be made (e.g. 'GET', 'POST', etc).

            path (str): URL path that the request is to be made to.
                This can be a relative path if a base url is provided when making the class.

            **kwargs: Additional arguments to be passed to the appropriate requests class method.

        Returns:
            Response object from requests library.
        """

        # We manually construct each request using Request objects, 
        #  PreparedRequest objects, and Session objects so we can print
        #  relevant information according to the options enabled.
        req = self._build_request(req_type, path, **kwargs)
        prep = self._prepare_request(req)
        res = self._send_request(prep)
        self._update_cookies(res)
        if self.raise_status:
            res.raise_for_status()
        self.print_request(self._req)
        self.print_response(self._res)
        return res

    def _update_cookies(self, response):
        if response.cookies:
            #for cookie in response.cookies:
                #self._cookies.update(cookie)
            self._cookies.update(response.cookies)
            #print("NEW COOKIES SENT.")

    def _build_request(self, request_type, path, **kwargs):
        """Create the Request object for a request.
        This allows for detailed output about the construction of a request.

        Args:
            req_type (str): The type of request to be made (e.g. 'GET', 'POST', etc).

            path (str): URL path that the request is to be made to.
                This can be a relative path if a base url is provided when making the class.

            **kwargs: Additional arguments to be passed to the appropriate requests class method.

        Returns:
            Response object from requests library.
        """
        existing_params = self._find_existing_params(path)
        if existing_params and ('params' in kwargs): # merge parameters in request
            # extract the parameters from the path given
            k_v = existing_params.split('&')
            k_v = list(map(lambda x: x.split('='), k_v))
            k_v = {unquote(a[0]): unquote(a[1]) for a in k_v}
            
            # params argument takes precedent over url params
            if 'params' in kwargs:
                for k, v in kwargs['params'].items():
                    k_v[k] = v
            # remove params from path, and update params kwarg
            path = self._find_url_without_params(path)
            kwargs['params'] = k_v


        if self.url:
            url = self.url + path
        else:
            url = path


        if not kwargs:
            kwargs = {}
        if not 'headers' in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['User-Agent'] = self._user_agent
        
        # Make form submission easier, it's annoying currently
        if 'form' in kwargs:
            #params = '&'.join([f"{quote(k)}={quote(v)}" for k,v in kwargs['form'].items()])
            # Start better input validation
            params = []
            if isinstance(kwargs['form'], dict):
                for k,v in kwargs['form'].items():
                    if isinstance(k, int):
                        k = str(k)
                    if isinstance(v, int):
                        v = str(v)
                    params.append(f"{quote(k)}={quote(v)}")
            elif isinstance(kwargs['form'], list):
                params = kwargs['form']
            # End better input validation
            params = '&'.join(params)
            kwargs['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
            kwargs['data'] = params
            del(kwargs['form'])

        self._req = requests.Request(   method = request_type, 
                                        url = url, 
                                        cookies = self._cookies,
                                        auth = self._auth,
                                        **kwargs)
        return self._req

    def _prepare_request(self, request):
        """Prepare the Request object to be sent to the web application.
        This method exists mostly as a precaution for future development.

        Args:
            request (Request): The request to be prepared.
        
        Returns:
            PreparedRequest object from requests library.
        """
        return request.prepare()

    def _send_request(self, prepared_request):
        """Send the PreparedRequest object to the web application.

        Args:
            prepared_request (PreparedRequest): The PreparedRequest object to be sent to the web application.

        Returns:
            Response object from requests library.
        """
        s = requests.Session()

        proxy = None
        if self.proxy_enabled:
            proxy = self._proxy

        # Send the request, verifying the response if the user has enabled
        #  this option.
        self._res = s.send( prepared_request, 
                            verify=self.verify, 
                            proxies=proxy)
        return self._res

    @property
    def all_request_output_options(self):
        """
        list: Valid request output options.
            method: Verb used for request (e.g. "GET", "POST", etc.).
            url: Full url being accessed with the request.
            headers: Header values sent with the request.
            body: Contents of the request.
            params: Parameters sent as part of the request.
            auth: Unused.
            cookies: Cookies sent with the request.
            hooks: Unused.
            mark: Denotes whether a string should be included to mark the beginning and
                end of requests.
        """
        return [
            'method',
            'url',
            'headers',
            'body',
            'params',
            'auth',
            'cookies',
            'hooks',
            'mark'
        ]

    @property
    def all_response_output_options(self):
        """
        list: Valid response output options.
            content: Content of the response.
                The format of this is affected by enable_json_output() and enable_pretty_json()
            cookies: CookieJar received as a response.
            elapsed: Timedelta between sending a request and parsing the response headers.
            headers: Headers sent in the response, as a dict.
            history: List of response objects from the history of the request. 
                This includes redirects that are encountered along the way.
            reason: Reason of status_code (e.g. "OK" or "Not Found").
            status_code: Status code of the response.
            url: Url that the request was sent to.
            mark: Denotes whether a string should be included to mark the beginning and
                end of requests.
        """
        return [
            'cookies',
            'content',
            'elapsed',
            'headers',
            'history',
            'reason',
            'status_code',
            'text',
            'url',
            'mark'
        ]

    def enable_all_request_output_options(self):
        """Enable all request output options."""
        self._set_all_request_output_options(True)

    def disable_all_request_output_options(self):
        """Disable all request output options."""
        self._set_all_request_output_options(False)

    def enable_all_response_output_options(self):
        """Enable all response output options."""
        self._set_all_response_output_options(True)
    
    def disable_all_response_output_options(self):
        """Disable all response output options."""
        self._set_all_response_output_options(False)

    def silent(self):
        """Disable all output options."""
        self.disable_all_request_output_options()
        self.disable_all_response_output_options()

    def silence(self):
        """Disable all output options."""
        self.silent()

    def verbose(self):
        """Enable all output options."""
        self.enable_all_request_output_options()
        self.enable_all_response_output_options()
        # Json output and prettification is enabled here because, if all output
        #  is wanted in the first place, readability is likely to be beneficial.
        self.enable_json_output()
        self.enable_pretty_json()

    def disable_warnings(self):
        """Disable ssl warnings."""
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)

    def enable_warnings(self):
        """Enable ssl warnings."""
        warnings.simplefilter('always', urllib3.exceptions.InsecureRequestWarning)

    def _set_all_request_output_options(self, value):
        """Set all request output options to the value specfied.

        Args:
            value (bool): The value to set the output options to.
        """
        for option in self.all_request_output_options:
            self._set_request_output_option(option, value)

    def _set_all_response_output_options(self, value):
        """Set all response output options to the value specfied.

        Args:
            value (bool): The value to set the output options to.
        """
        for option in self.all_response_output_options:
            self._set_response_output_option(option, value)

    def _set_request_output_option(self, option_name, value):
        """Set an individual request output option to the specified value.

        Args:
            option_name (str): The output option to be modified.
            value (bool): The value to set the output option to.
        """
        if value not in [True, False]:
            raise TypeError("ERROR: Attempted to set output option to non-boolean value.")
        if option_name not in self.all_request_output_options:
            raise OptionDoesNotExist("Option " + option_name + " does not exist.")
        self.req_output_options[option_name] = value

    def _set_response_output_option(self, option_name, value):
        """Set an individual response output option to the specified value.

        Args:
            option_name (str): The output option to be modified.
            value (bool): The value to set the output option to.
        """
        if value not in [True, False]:
            raise TypeError("ERROR: Attempted to set output option to non-boolean value.")
        if option_name not in self.all_response_output_options:
            raise OptionDoesNotExist("Option " + option_name + " does not exist.")
        self.res_output_options[option_name] = value
    
    def _has_enabled_request_output(self):
        """Check if any request output options are enabled.

        Returns:
            True if a respone output option is enabled, False otherwise.
        """
        for option in self.all_request_output_options:
            if self.req_output_options[option] == True:
                return True
        return False

    def _has_enabled_response_output(self):
        """Check if any response output options are enabled.

        Returns:
            True if a respone output option is enabled, False otherwise.
        """
        for option in self.all_response_output_options:
            if self.res_output_options[option] == True:
                return True
        return False

    def enable_request_output_option(self, option_name):
        """Enable an specific request output option."""
        self._set_request_output_option(option_name, True)

    def disable_request_output_option(self, option_name):
        """Disable an specific request output option."""
        self._set_request_output_option(option_name, False)

    def enable_response_output_option(self, option_name):
        """Enable an specific response output option."""
        self._set_response_output_option(option_name, True)

    def disable_response_output_option(self, option_name):
        """Enable an specific response output option."""
        self._set_response_output_option(option_name, False)

    def enable_response_output_options(self, option_list):
        for item in option_list:
            self._set_response_output_option(item, True)

    def disable_response_output_options(self, option_list):
        for item in option_list:
            self._set_response_output_option(item, False)

    def enable_request_output_options(self, option_list):
        for item in option_list:
            self._set_request_output_option(item, True)

    def disable_request_output_options(self, option_list):
        for item in option_list:
            self._set_request_output_option(item, False)

    def enable_json_output(self):
        """Enable printing response as json content if applicable."""
        self.json_output = True

    def disable_json_output(self):
        """Disable printing response as json content if applicable."""
        self.json_output = False

    def enable_pretty_json(self):
        """Enable prettified json output."""
        self.prettify_json = True

    def disable_pretty_json(self):
        """Disable prettified json output."""
        self.prettify_json = False

    def enable_verification(self):
        """Enable ssl verification enforcement."""
        self.verify = True

    def disable_verification(self):
        """Disable ssl verification enforcement."""
        self.verify = False

    def set_default_request_output_options(self):
        """Enable default request output options."""
        self.disable_all_request_output_options()
        self.enable_request_output_option('url')
        self.enable_request_output_option('method')

    def set_default_response_output_options(self):
        """Enable default response output options."""
        self.disable_all_response_output_options()
        self.enable_response_output_option('status_code')

    def enable_raise_for_status(self):
        """Enable the Response.raise_for_status() call when making requests."""
        self.raise_status = True

    def disable_raise_for_status(self):
        """Disable the Response.raise_for_status() call when making requests."""
        self.raise_status = False

    def _url_encode_param_dict(self, params):
        """Convert a parameter dictionary to url-encoded string format.

        Args:
            params (dict): Parameters to encode.

        Returns:
            Url-encoded string of parameters dictionary.
        """
        # Converts the dict to this format:
        # ?param1=val1&param2=val2&param3=val3
        # Sorted for consistency
        #param_list = [f"{quote(k)}={quote(v)}" for k,v in kwargs['form'].items()]
        param_list = []
        # Start better validation
        if isinstance(params, dict):
            for k,v in params.items():
                if isinstance(k, int):
                    k = str(k)
                if isinstance(v, int):
                    v = str(v)
                param_list.append(f"{quote(k)}={quote(v)}")
        else:
            raise TypeError("Invalid type passed as form kwarg.")
        """
        if isinstance(kwargs['form'], dict):
            for k,v in kwargs['form'].items():
                if isinstance(k, int):
                    k = str(k)
                if isinstance(v, int):
                    v = str(v)
                param_list.append(f"{quote(k)}={quote(v)}")
        elif isinstance(kwargs['form'], list):
            param_list = '&'.join(kwargs['form'])
        else:
            raise TypeError("Invalid type passed as form kwarg.")
        """
        # End better validation
        param_list.sort()
        return '?' + '&'.join(param_list)

    def _param_dict_to_string(self, params):
        """Convert a parameter dictionary to string format.

        Args:
            params (dict): Parameters to encode.

        Returns:
            String encoding of parameters dictionary.
        """
        # Converts the dict to this format:
        # param1=val1&param2=val2&param3=val3
        # Sorted for consistency
        params = ['{}={}'.format(k, v) for k, v in params.items()]
        params.sort()
        return '&'.join(params)

    def _find_existing_params(self, string):
        """Determine if there are existing params in the URL, and return them.

        Args:
            string (str): The url string to find parameters in.

        Returns:
            Substring containing the key-value pairs of parameters in the given string, if a match is found. Returns None otherwise.
        """
        # Find question mark, and collect everything up to a pound symbol
        param_regex = r"[A-Za-z0-9-._~!$&'()*+,;=:@/][^?#]*\?(?P<path>[^#]*)"
        match = re.match(param_regex, string)
        if not match:
            return None
        return match.group('path')

    def _find_url_without_params(self, url):
        """Determine the base URL without parameters, and return it.

        Args:
            string (str): The url string to find the base of.

        Returns:
            Substring containing the base url in the given string, and the fragment if it exists.
        """
        # Find question mark, and collect everything up to said question mark
        param_regex = r"(?P<url>[A-Za-z0-9-._~!$&'()*+,;=:@/][^?#]*)\?[^#]*(?P<fragment>#.*)?"
        match = re.match(param_regex, url)
        return match.group('url')

    @classmethod
    def fill_line(self, string):
        """Create a string which is surrounded by '=' characters, to stand out in stdout.

        Returns:
            String surrounded with '=' characters, expanded as necessary to 79/80 characters.
        """
        # Always add at least 3 equal signs on either side
        # Fill up to 79/80 characters symmetrically when possible.
        string = '=== ' + string + ' ==='
        if((len(string) + 2) < 80):
            diff = 80 - len(string)
            string = '='*int(diff/2) + string + '='*int(diff/2)
        return string

    def print_request(self, req):
        """Print details about each request that is made.
        This method is called whenever a request is made, so output options should be customized for your application.

        Args:
            req (Request): The request to be printed.
        """
        # Break early if we can
        if(not self._has_enabled_request_output()):
            return
        # Mark the beginning of the request as necessary
        if(self.req_output_options['mark']):
            print("\n\n" + Session.fill_line("BEGIN REQUEST") + "\n\n")
        method_url = ''
        # Output the request method as necessary
        if(self.req_output_options['method']):
            method_url += req.method + ' '
        # Output the request url and parameters as necessary
        if(self.req_output_options['url'] or self.req_output_options['params']):
            method_url += req.url
            if(req.params):
                method_url += self._url_encode_param_dict(req.params)
        if(len(method_url) > 0):
            print(method_url)
        # Output headers and cookies as necessary
        if(self.req_output_options['headers']):
            if len(req.headers.items()) > 0:
                print('\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()))
            if req.cookies:
                print("Cookies:")
                for cookie in req.cookies:
                    print(f"{cookie.name}: {cookie.value}")
        # Output body of the request as necessary
        if(self.req_output_options['body']):
                if req.files or req.data or req.json:
                    print()
                    if(req.files):
                        print(req.files)
                    if(req.data):
                        print(req.data)
                    if(req.json):
                        print(req.json)
        # Mark the end of the request as necessary
        if(self.req_output_options['mark']):
            print("\n\n" + Session.fill_line("END REQUEST") + "\n\n")
        return

    def print_response(self, res):
        """Print details about each response that is made.
        This method is called whenever a response is made, so output options should be customized for your application.

        Args:
            res (Response): The response to be printed.
        """
        # Break early if we can
        if(not self._has_enabled_response_output()):
            return
        # Mark the beginning of the response as necessary
        if(self.res_output_options['mark']):
            print("\n\n" + Session.fill_line("BEGIN RESPONSE") + "\n\n")

        # Print request history if necessary
        # We shouldn't need to print full request details for everything
        #  in the request history, so we only print status and content.
        if((len(res.history) > 0) and self.res_output_options['history']):
            print("\nRequest history:")
            for element in res.history:
                print(f"    {element}")
                print(f"    {element.status_code} {element.url}")
            print("End request history.\n")

        # Print url as necessary
        status_code_output = ""
        if(self.res_output_options['url']):
            status_code_output = res.url
            if self.res_output_options['status_code'] or self.res_output_options['reason']:
                status_code_output += ' -- '

        # Print status_code and reason as necessary
        # Printing the reason without the status code doesn't make sense, so
        #  these are tied together.
        if(self.res_output_options['status_code'] or self.res_output_options['reason']):
            status_code_output += str(res.status_code)
            if self.res_output_options['reason']:
                status_code_output += ' ' + res.reason
            print(status_code_output)

        # Print elapsed time as necessary
        if(self.res_output_options['elapsed']):
            print('Time elapsed: ' + str(res.elapsed))

        # Print headers and cookies necessary
        if(self.res_output_options['headers']):
            print('\n'.join('{}: {}'.format(k, v) for k, v in res.headers.items()))
        if(self.res_output_options['cookies']):
            if res.cookies:
                print("Cookies: ")
                for cookie in res.cookies:
                    print(f"{cookie.name}: {cookie.value}")

        # Print content in the manner specified by the settings chosen.
        if(self.res_output_options['content']):
            try:
                if self.json_output:
                    if self.prettify_json:
                        print(json.dumps(res.json(),indent=2))
                    else:
                        print(res.json())
                else:
                    print(res.content)
            except Exception as e: # Not json
                print(res.content)

        # Mark the end of the response as necessary
        if self.res_output_options['mark']:
            print("\n\n" + Session.fill_line("END RESPONSE") + "\n\n")

    def disable_proxy(self):
        """Disable request proxying."""
        self._proxy_enabled = False

    def enable_proxy(self):
        """Enable request proxying."""
        self._proxy_enabled = True

    @property
    def proxy_enabled(self):
        """Current proxy status."""
        return self._proxy_enabled

    def set_proxy(self, proxy_type, address, port=None):
        """Set proxy details.

        Args:
            proxy_type (str): Type of request to proxy.
            address (str): Address to proxy through.
            port (str): Port to use at proxy address.
                If this is not set, it is assumed to be included in the address.
        """
        if port:
            full_proxy_address = ':'.join((address,str(port)))
        else:
            full_proxy_address = address
        self._proxy[proxy_type] = full_proxy_address

    @property
    def cookies(self):
        """Cookie jar used for keeping track of state across requests."""
        return self._cookies

    @property
    def url(self):
        """Url associated with the Session object."""
        return self._url

    def clear_cookies(self):
        """Clears the cookies associate with the Session object."""
        self._cookies = requests.cookies.RequestsCookieJar()

    @property
    def user_agent(self):
        return self._user_agent
    
    @user_agent.setter
    def user_agent(self, val):
        self._user_agent = val
