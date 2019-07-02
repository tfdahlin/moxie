#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: moxie/tests/test_all.py
from unittest import TestCase
from ..tests import SimpleServer, SERVER_URL, HTTPS_SERVER_URL
from .. import Session, OptionDoesNotExist
import requests, io, sys, time
from contextlib import contextmanager

# Used to capture output for the output tests
# Thanks to this stackoverflow answer https://stackoverflow.com/a/17981937
@contextmanager
def captured_output():
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

class TestSession(TestCase):
    """Test the functionality of the Session object."""
    def test_delete_request(self):
        """Test DELETE method."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.delete('/')
        assert res.json()['success'], 'Request not successful.'
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'DELETE', 'Wrong request type.'

    def test_get_request(self):
        """Test GET method."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.get('/')
        assert res.json()['success'], 'Request not successful.'
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'GET', 'Wrong request type.'

    def test_cookie_tracking(self):
        """Test that cookies are tracked."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cookie_update_test')
        assert sess.cookies['step'] == '1', 'Cookies not incremented properly.'
        sess.get('/cookie_update_test')
        assert sess.cookies['step'] == '2', 'Cookies not incremented properly.'

    def test_cookie_no_update(self):
        """Test that cookies are retained during session when no set-cookie header exists."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/')
        assert sess.cookies['step'] == '1', 'Cookies not incremented properly.'
        sess.get('/no-update-cookie')
        assert sess.cookies['step'] == '1', 'Cookies not maintained properly.'

    def test_head_request(self):
        """Test HEAD method."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.head('/')
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'HEAD', 'Wrong request type.'

    def test_options_request(self):
        """Test OPTIONS method."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.options('/')
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'OPTIONS', 'Wrong request type.'

    def test_post_request(self):
        """Test POST method."""
        my_string_file = io.StringIO()
        my_string_file.write('This is a text file.\r\n\r\n'*100)
        data = {
            'foo&': '&bar',
            'bar': 'foo'
        }
        files = {
            'my_file.txt': bytes(my_string_file.getvalue(), 'utf-8')
        }
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.verbose()
            res = sess.post('/', data=data, files=files, json=data, params=data)
        assert res.json()['success'], 'Request not successful.'
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'POST', 'Wrong request type.'

    def test_put_request(self):
        """Test PUT method."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.put('/', data={'foo': 'bar'})
        assert res.json()['success'], "Request not successful."
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'PUT', "Wrong request type."

    def test_dict_to_string(self):
        """Test converting dict to paramater string."""
        my_dict = {
            'other_foo': 'other_bar',
            'foo': 'bar'
        }
        sess = Session(SERVER_URL)
        sess.silence()
        stringified = sess._param_dict_to_string(my_dict)
        assert stringified == 'foo=bar&other_foo=other_bar', 'Dict to string failed.'

    def test_url_encode_param_dict(self):
        """Test URL-encoding parameter dict."""
        my_dict = {
            'foo': 'bar',
            'other foo': 'other bar',
        }
        sess = Session(SERVER_URL)
        sess.silence()
        stringified = sess._url_encode_param_dict(my_dict)
        assert stringified == '?foo=bar&other%20foo=other%20bar', 'Url-encoding param dict failed.'

    def test_fill_line(self):
        """Test the fill line method associated with the mark options."""
        # Short strings lengthened to 79-80 characters
        starting_string = "This is a string"
        filled_string = Session.fill_line(starting_string)
        correct_start = filled_string.startswith('=')
        correct_end = filled_string.endswith('=')
        correct_length = ((len(filled_string) == 79) or (len(filled_string) == 80))
        contains_original = starting_string in filled_string

        assert contains_original, 'String mangled.'
        assert correct_length, 'String too short.'
        assert correct_start, 'Does not start with "=".'
        assert correct_end, 'Does not end with "=".'

        # Long strings just put '=' characters on either side
        longer_string = "Longer string"*10
        filled_string = Session.fill_line(longer_string)
        correct_start = filled_string.startswith('=')
        correct_end = filled_string.endswith('=')
        correct_length = len(filled_string) > 78
        contains_original = longer_string in filled_string

        assert contains_original, 'String mangled.'
        assert correct_length, 'String too short.'
        assert correct_start, 'Does not start with "=".'
        assert correct_end, 'Does not end with "=".'

    def test_verbose(self):
        """Test verbose output."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.silence()
            sess.get('/verbose_test')
            sess.verbose()
            sess.get('/verbose_test', headers={'Accept': 'text/html'})
            output = out.getvalue().strip()
        #print(output)
        assert 'GET ' + SERVER_URL in output, 'Get request not printed.'
        assert 'step: 2' in output, 'Cookies not printed.'
        assert 'Time elapsed' in output, 'Time elapsed not printed.'
        assert 'Set-Cookie' in output, 'Cookie not printed.'
        assert 'X-TEST-REQUEST_TYPE: GET' in output, 'Response header not printed.'
        assert '"success": true' in output, 'Success not printed.'

    def test_raise_404(self):
        """Test 404 detection."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.enable_raise_for_status()
        try:
            sess.get('/404')
        except Exception:
            pass
        else:
            raise 'Raise_for_status failed.'

    def test_enable_invalid_output_options(self):
        """Test enabling invalid output option detection."""
        sess = Session(SERVER_URL)
        sess.silence()
        try:
            sess.enable_response_output_option('not_a_real_option')
        except OptionDoesNotExist:
            pass
        else:
            raise 'Invalid output option allowed.'
        try:
            sess.enable_request_output_option('not_a_real_option')
        except OptionDoesNotExist:
            pass
        else:
            raise 'Invalid output option allowed.'

    def test_disable_invalid_output_options(self):
        """Test disabling invalid output options."""
        sess = Session(SERVER_URL)
        sess.silence()
        try:
            sess.disable_response_output_option('not_a_real_option')
        except OptionDoesNotExist:
            pass
        else:
            raise 'Invalid output option allowed.'
        try:
            sess.disable_request_output_option('not_a_real_option')
        except OptionDoesNotExist:
            pass
        else:
            raise 'Invalid output option allowed.'

    def test_invalid_output_option_setting(self):
        """Test setting output option to invalid value."""
        sess = Session(SERVER_URL)
        sess.silence()
        try:
            sess._set_request_output_option('mark', 'inavlid_option')
        except Exception:
            pass
        else:
            raise 'Invalid output option setting allowed.'
        try:
            sess._set_response_output_option('mark', 'inavlid_option')
        except Exception:
            pass
        else:
            raise 'Invalid output option setting allowed.'

    def test_enable_and_disable_multiple_response_options(self):
        """Test enabling and disabling of response output options as lists."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.enable_response_output_options(['content', 'elapsed'])

        assert sess.res_output_options['content'], 'Content response output option not enabled.'
        assert sess.res_output_options['elapsed'], 'Elapsed response output option not enabled.'

        sess.disable_response_output_options(['content', 'elapsed'])
        assert not sess.res_output_options['content'], 'Content response output option not disabled.'
        assert not sess.res_output_options['elapsed'], 'Elapsed response output option not disabled.'

    def test_enable_and_disable_multiple_request_options(self):
        """Test enabling and disabling of request output options as lists."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.enable_request_output_options(['body', 'params'])

        assert sess.req_output_options['body'], 'Body response output option not enabled.'
        assert sess.req_output_options['params'], 'Params response output option not enabled.'

        sess.disable_request_output_options(['body', 'params'])
        assert not sess.req_output_options['body'], 'Body response output option not disabled.'
        assert not sess.req_output_options['params'], 'Params response output option not disabled.'

    def test_silence(self):
        """Test silenced output."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.silence()
            sess.get('/')
            output = out.getvalue().strip()
            assert len(output) == 0, 'Silence failed.'

    def test_get_url(self):
        """Test fetching Session URL."""
        sess = Session(SERVER_URL)
        sess.silence()
        url_from_session = sess.url
        assert url_from_session == SERVER_URL, 'URL does not match.'

    def test_clear_cookies(self):
        """Test clearing cookies."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/')
        assert sess.cookies['step'] == '1', 'Cookies not set correctly'
        sess.clear_cookies()
        assert len(sess.cookies.keys()) == 0, 'Cookies not cleared correctly'
        
    def test_no_base_url(self):
        """Test making a request without a base url."""
        sess = Session()
        sess.silence()
        res = sess.get(SERVER_URL + '/')
        assert res.json()['success'], 'Request not successful.'
        assert res.headers['X-TEST-REQUEST_TYPE'] == 'GET', 'Wrong request type.'

    def test_ssl(self):
        """Test SSL certificate verification."""
        sess = Session(HTTPS_SERVER_URL)
        sess.silence()
        sess.enable_verification()
        try:
            res = sess.get('/')
        except:
            pass
        else:
            raise "SSL verification not enforced."
        sess.disable_verification()
        res = sess.get('/')

    def test_find_existing_params(self):
        """Test finding existing parameters in a URL."""
        sess = Session(SERVER_URL)
        sess.silence()
        result = sess._find_existing_params(SERVER_URL + '/?foo=bar')
        assert result, 'Params not found when they exist.'
        result = sess._find_existing_params(SERVER_URL)
        assert not result, 'Params found when they do not exist.'

    def test_with_redirect(self):
        """Test request history output after redirect."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.verbose()
            sess.get('/redirect')
            output = out.getvalue().strip()
            assert 'Request history' in output, 'Request history not printed.'

    def test_enable_warnings(self):
        """Test re-enabling warnings."""
        with captured_output() as (out, err):
            sess = Session(HTTPS_SERVER_URL)
            sess.disable_verification()
            sess.enable_warnings()
            sess.get('/')
            error = err.getvalue().strip()
            assert 'Unverified HTTPS request is being made.' in error, 'Warning not enabled.'

    def test_no_pretty_json(self):
        """Test disabled pretty json output."""
        with captured_output() as (out, err):
            sess = Session(HTTPS_SERVER_URL)
            sess.enable_response_output_option('content')
            sess.disable_pretty_json()
            sess.get('/')
            output = out.getvalue().strip()
            assert '\'success\': True' in output

    def test_no_json(self):
        """Test disabled json output."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.enable_response_output_option('content')
            sess.disable_json_output()
            sess.get('/')
            output = out.getvalue().strip()
            assert 'b\'{"success": true' in output

    def test_not_json_response(self):
        """Test non-json response processing."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.enable_response_output_option('content')
            sess.get('/non-json')
            output = out.getvalue().strip()
            assert 'b\'<!DOCTYPE html>' in output

    def test_param_append(self):
        """Test that parameter arguments and URL parameters are correctly pieced together."""
        with captured_output() as (out, err):
            sess = Session(SERVER_URL)
            sess.get('/?foo=bar&food=bard', params={'foo': 'new'})
            output = out.getvalue().strip()
            assert '?foo=new' in output, 'Request params not correctly updated.'
        
    def test_basic_auth(self):
        """Test that basic auth credentials are transmitted correctly."""
        sess = Session(SERVER_URL, auth_user='user', auth_pass='pass')
        sess.silence()
        res = sess.get('/check-auth/user:pass')
        assert res.json()['success']

    def test_form_with_empty_params(self):
        """Test that the form argument works properly."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.post('/', form={'foo': 'bar'})
        assert 'foo=bar' in sess._req.data, 'Form not converted to data.'

    def test_form_with_existing_params(self):
        """Test that the form argument updates params in a url."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.post('/?foo=bar&foo2=bar2', form={'foo': 'new'})
        assert 'foo=new' in sess._req.data, 'Parameter not updated.'

    def test_convert_int_params_to_string(self):
        """Make sure that ints passed in form kwarg are converted to strings."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.post('/', form={1:2})
        assert '1=2' in sess._req.data, 'Form not converted correctly.'

    def test_form_as_list(self):
        """Test that lists work correctly for the form argument."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.post('/', form=['foo=bar','1=2'])
        assert 'foo=bar' in sess._req.data, 'List not converted to params properly.'
        assert '1=2' in sess._req.data, 'List not converted to params properly.'

    def test_proxy(self):
        """Test a proxy."""
        #return
        sess = Session(SERVER_URL)
        #sess.verbose()
        sess.silence()
        sess.enable_proxy()
        assert sess.proxy_enabled, 'Proxy not enabled.'

        # Test proxy with given port as argument
        sess.set_proxy('http', '127.0.0.1', '9003')
        res = sess.get('/')
        assert res.status_code == 200, 'Proxy was not successful.'

        sess.set_proxy('http', '127.0.0.1:9003')
        res = sess.get('/')
        assert res.status_code == 200, 'Proxy was not successful.'

        sess.disable_proxy()
        assert not sess.proxy_enabled, 'Proxy not disabled.'

    def test_url_encode_param_dict_with_ints(self):
        """Test that url-encoding a param dict with integers works."""
        sess = Session(SERVER_URL)
        sess.silence()
        result = sess._url_encode_param_dict({1:2, 2:3})
        assert result == '?1=2&2=3'

    def test_fail_url_encode_non_list_dict(self):
        """Test that a TypeError is raised when neither list nor dict is passed."""
        sess = Session(SERVER_URL)
        sess.silence()
        try:
            result = sess._url_encode_param_dict('foo=bar')
        except TypeError as e:
            pass
        else:
            raise Exception('Failed to raise exception for non-list/dict.')

    def test_get_user_agent(self):
        """Test that the user agent can be accessed."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.user_agent = 'Test User Agent'
        assert sess.user_agent == 'Test User Agent', 'User agent cannot be read.'

    def test_no_store(self):
        """Test that no caching occurs when the no-store cache-control is sent."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cache/no-store')
        assert '/cache/no-store' not in sess._cache, sess._cache['/cache/no-store']

    def test_no_cache_304(self):
        """Test that a request to the same resource with no-cache specified returns 304 code."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cache/no-cache')
        res = sess.get('/cache/no-cache')
        assert res.status_code == 304, '304 not returned for cached result.'

    def test_no_cache_mismatch(self):
        """Test that a request sent to the same resource twice with a mismatched ETag returns 200."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cache/no-cache/mismatch')
        res = sess.get('/cache/no-cache/mismatch')
        assert res.status_code == 200, '200 not returned for mismatched ETag.'

    def test_no_cache_max_age(self):
        """Test that a request to the same resource twice with a max-age header set returns 200 when the max-age expires."""
        sess = Session(SERVER_URL)
        sess.silence()
        # Make a request to the same resource twice, where the max-age header is sent.
        sess.get('/cache/no-cache')
        res = sess.get('/cache/no-cache')
        assert res.status_code == 304, '304 not returned for cached result without max-age response.'
        sess.get('/cache/no-cache/short')
        time.sleep(3)
        res = sess.get('/cache/no-cache/short')
        assert res.status_code == 200, '200 not returned for expired cache.'

    def test_no_cache_no_etag_304(self):
        """Test that a request sent to the same resource twice with no etag the second time returns 304."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cache/no-cache/no-etag')
        res = sess.get('/cache/no-cache/no-etag')
        assert res.status_code == 304, '304 not returned for cached result without etag response.'

    def test_cache_result(self):
        """Test that a request to the same resource twice with a max-age set returns a cached result the second time."""
        sess = Session(SERVER_URL)
        sess.silence()
        sess.get('/cache/')
        res = sess.get('/cache/')
        assert res.status_code == 200, '200 not returned for cached result with max-age set.'
        assert res.reason == '(cache)', '200 Returned for cached result, but \'(cache}\' reason not mentioned.'

    def test_no_cache_no_max_age(self):
        """Test that a request to the same resource twice with no max-age sent the second time returns 304."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.get('/cache/no-cache/no-max-age')
        res = sess.get('/cache/no-cache/no-max-age')
        assert res.status_code == 304, '304 not returned for no-max-age request.'

    def test_cache_no_max_age(self):
        """Test that a request to the same resource twice with no max-age sent the first time sets cache max-age to zero."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.get('/cache/no-max-age')
        time.sleep(1)
        res = sess.get('/cache/no-max-age')
        assert res.status_code == 200, '200 not returned for no-max-age request.'

    def test_cache_controls_empty(self):
        """Test that data isn't cached when the cache-control header is empty."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.get('/cache/empty')
        res = sess.get('/cache/empty')
        assert res.status_code == 200, '200 not returned for empty cache-control.'

    def test_clear_cache(self):
        """Test that clearing the cache results in a 200 response the second time."""
        sess = Session(SERVER_URL)
        sess.silence()
        res = sess.get('/cache')
        sess.clear_cache()
        res = sess.get('/cache')
        assert res.status_code == 200, '200 not returned for GET request to /cache'
        assert res.reason != '(cache)', 'Request not cached.'

    def test_authorization_header(self):
        """Test that basic auth credentials are printed."""
        sess = Session(SERVER_URL, auth_user='user', auth_pass='pass')
        sess.silence()
        with captured_output() as (out, err):
            sess.enable_request_output_option('auth')
            res = sess.get('/check-auth/user:pass')
            output = out.getvalue().strip()
        assert 'Authorization' in output, 'Authorization header not printed.'
