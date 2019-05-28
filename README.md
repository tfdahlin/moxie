# Moxie -- A simple Python Requests wrapper
I'm a huge fan of the [Python Requests library][1], and have used it extensively for my work to automate tasks. However, I have found myself writing a lot of the same code repeatedly to accomplish some of the same tasks. Frequently, I need to see what a request actually looks like when it is being sent so I can debug the interaction, and the Requests library makes this a bit of a tedious process. The goal of this package is to not only to simplify debugging of requests by allowing for dynamic modification of output options, but also to manage state in the same way the Session object that Requests provides.

## Installation
1. Make sure you have python3 and python3-pip installed on your system.
2. Clone the moxie repository, then navigate into the top level of the repository.
3. Run `pip install .` to install the package.

## Usage
If you've used the Python Requests library before, transitioning to using this library should be fairly straightforward. One immediate difference you'll notice is a difference in output. SSL certificate warnings and verification are disabled by default. This is useful for development, because self-signed certificates are common for local environments. Additionally, the URL and method for each request and the status code for each response are output by default. For more information, see the customizing output section.

#### Getting started
To start, create a new Session object:
~~~~
#!/usr/bin/evn python
from moxie import Session

session_with_base_url = Session('http://example.com')
session_without_url = Session()
~~~~
This will create a new browser-like object that can be used to interact with a web application. A session object can be created with or without a base URL. If a base URL is used, all requests made with that object should be relative. If no base URL is used, requests should be absolute paths.
#### Making a GET request
Example GET requests to a homepage might look like these:
~~~~
from moxie import Session

s = Session('http://example.com') # request with base url
s.get('/')

s = Session() # request without base url
s.get('http://example.com/')
~~~~
#### Making other types of requests
###### Post Request
An example of a POST request might look like this:
~~~~
from moxie import Session

login_info = {
    'username': 'Cr4sh_0v3rr1d3',
    'password': 'hunter2'
}
s = Session('http://example.com')
s.post('/login', data=login_info)
~~~~
###### Put Request
An example of a PUT request might look like this:
~~~~
from moxie import Session

login_info = {
    'username': 'th3_pl4gu3',
    'password': 'god'
}
s = Session('http://example.com')
s.put('/register', data=login_info)
~~~~
###### Supported request types
Currently, this library supports the following request types:
 - DELETE
 - GET
 - HEAD
 - OPTIONS
 - POST
 - PUT

#### Customizing output
A big focus for this library was to make the output easily customizeable to suit the needs of your application. As mentioned above, there are some default output options that are set whenever a Session object is created. Most of the output options are separated into two categories: request and response output options. Let's delve a little deeper into each of these.
##### Request output options
 - method: Verb used for the request (e.g. "GET", "POST", etc.)
 - url: Full url being accessed with the request
 - headers
 - body: Contents of the request
 - params: Parameters sent as part of the request
 - auth: Currently unused
 - cookies
 - hooks: Currently unused
 - mark: Denotes whether strings should be used to mark the beginning and end of a request

##### Response output options
 - content: Content of the response
 - cookies
 - elapsed: Timedelta between sending the request and parsing the response headers
 - headers
 - history: List of response objects from the history of request, such as redirects
 - reason: Reason of status code (e.g. "OK" or "Not Found")
 - status_code
 - url: Url that the request was sent to
 - mark: Denotes whether strings should be used to mark the beginning and end of a request

##### Changing request and response output options
By default, the `url` and `method` request options, as well as the `status_code` response option are enabled. The Session object has a few methods for changing which options are enabled: `[enable/disable]_response_output_option(option_name)` and `[enable/disable]_request_output_option(option_name)`. As an example, if you wanted to disable the url and method output, you would do this:
~~~~
from moxie import Session

s = Session('http://example.com')
s.disable_request_output_option('url')
s.disable_request_output_option('method')
~~~~
There are also a few methods for enabling or disabling all output: `[enable/disable]_all_request_output_options()` and `[enable/disable]_all_response_output_options()` will enable or disable all output for requests or response. Alternatively, if you want to enable disable all output altogether, you can use `verbose()`, `silent()`, or `silence()`; these methods apply to both requests and responses.

###### Additional output options
There are also a few output options that pertain to formatting. When a response is received, it's in a bytes format. While this can be useful for processing purposes, it's less useful to read. In order to provide more readable output, the Session object has options for attempting to convert a response to json instead of bytes, and pretty-printing the json. These options are enabled by default, and can be modified with the `[enable/disable]_json_output()` and `[enable/disable]_pretty_json()` methods.

#### Miscellaneous functionality
There are a few additional features that may be useful in some cases.
 - `Session.clear_cookies()` clears the cookies of the session. Most of the time, creating a new session will be more useful.
 - `Session.cookies` will provide the internal cookies of the Session object. This could be useful for program logic, but consider using the output options instead if all you need to do is see the content.
 - `Session.url` provides access to the base url of the Session. If there is no base url, the base url defaults to None.
 - `form` kwarg can be passed as a dictionary to a request to automatically set the `Content-Type` to `application/x-www-form-urlencoded` and convert the dictionary to a url-encoded string, to pass as the body of the request.

#### TODO
 - Caching of web requests

### See also
[Requests: HTTP for Humans][1]
[Hackers (1995)][2]

[1]: https://python-requests.org/ "Requests: HTTP for Humans"
[2]: https://www.imdb.com/title/tt0113243/ "Hackers (1995)"
