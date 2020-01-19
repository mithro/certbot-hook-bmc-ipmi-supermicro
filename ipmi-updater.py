#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# This file is part of Supermicro IPMI certificate updater.
# Supermicro IPMI certificate updater is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia


import os
import argparse
import requests
from datetime import datetime
from lxml import etree
from urllib.parse import urlparse
import time

# Debug connections
import logging
import http.client as http_client

# For overwritten_encode_files()
from urllib3.fields import RequestField
from urllib3.filepost import encode_multipart_formdata
from requests.utils import (
    guess_filename, get_auth_from_url, requote_uri,
    stream_decode_response_unicode, to_key_val_list, parse_header_links,
    iter_slices, guess_json_utf, super_len, check_header_validity)
from requests.compat import (
    Callable, Mapping,
    cookielib, urlunparse, urlsplit, urlencode, str, bytes,
    is_py2, chardet, builtin_str, basestring)

REQUEST_TIMEOUT = 5.0

LOGIN_URL = '%s/cgi/login.cgi'
IPMI_QUERY_URL = '%s/cgi/ipmi.cgi'
UPLOAD_CERT_URL = '%s/cgi/upload_ssl.cgi'
REBOOT_IPMI_URL = '%s/cgi/BMCReset.cgi'
MAIN_FRAME_URL = '%s/cgi/url_redirect.cgi?url_name=mainmenu'
CONFIG_CERT_URL = '%s/cgi/url_redirect.cgi?url_name=config_ssl'


def login(session, url, username, password):
    """
    Log into IPMI interface
    :param session: Current session object
    :type session requests.session
    :param url: base-URL to IPMI
    :param username: username to use for logging in
    :param password: password to use for logging in
    :return: bool
    """

    # Prime
    try:
        result = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False

    if not result.ok:
        return False

    # Do the actual login
    login_data = {
        'name': username,
        'pwd': password
    }

    login_url = LOGIN_URL % url
    try:
        result = session.post(login_url, login_data, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    if '/cgi/url_redirect.cgi?url_name=mainmenu' not in result.text:
        return False

    # Prime again
    frame_url = CONFIG_CERT_URL % url
    try:
        result = session.get(frame_url, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False

    if result.headers['Content-Type'] != 'text/html':
        return False
    if '?SSL_STATUS.XML=(0,0)&time_stamp=' not in result.text:
        return False

    return True


def get_ipmi_cert_info(session, url):
    """
    Verify existing certificate information
    :param session: Current session object
    :type session requests.session
    :param url: base-URL to IPMI
    :return: dict
    """
    # SSL_STATUS.XML=(0,0)&time_stamp=Fri Nov 09 2018 18:51:38 GMT+0200 (Eastern European Standard Time)
    timestamp = datetime.utcnow().strftime('%a %d %b %Y %H:%M:%S GMT')
    cert_info_data = {
        # '_': '',
        'SSL_STATUS.XML': '(0,0)',
        'time_stamp': timestamp  # 'Thu Jul 12 2018 19:52:48 GMT+0300 (FLE Daylight Time)'
    }

    ipmi_headers = {
        "Origin": url,
        "X-Requested-With": "XMLHttpRequest"
    }
    ipmi_info_url = IPMI_QUERY_URL % url
    try:
        result = session.post(ipmi_info_url, cert_info_data,
                              headers=ipmi_headers, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False
    if result.headers['Content-Type'] != 'application/xml':
        return False

    root = etree.fromstring(result.text)
    # <?xml> <IPMI> <SSL_INFO> <STATUS>
    status = root.xpath('//IPMI/SSL_INFO/STATUS')
    if not status:
        return False
    # Since xpath will return a list, just pick the first one from it.
    status = status[0]
    has_cert = int(status.get('CERT_EXIST'))
    has_cert = bool(has_cert)
    if has_cert:
        valid_from = status.get('VALID_FROM')
        valid_until = status.get('VALID_UNTIL')

    return {
        'has_cert': has_cert,
        'valid_from': valid_from,
        'valid_until': valid_until
    }


def prepare_for_cert_upload(session, url):
    timestamp = datetime.utcnow().strftime('%a %d %b %Y %H:%M:%S GMT')
    cert_info_data = {
        'SSL_VALIDATE.XML=(0,0)'
        'time_stamp': timestamp  # 'Thu Jul 12 2018 19:52:48 GMT+0300 (FLE Daylight Time)'
    }

    ipmi_headers = {
        "Origin": url,
        "X-Requested-With": "XMLHttpRequest"
    }
    ipmi_info_url = IPMI_QUERY_URL % url
    try:
        result = session.post(ipmi_info_url, cert_info_data,
                              headers=ipmi_headers, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False

    # Don't try to parse XML, if response isn't one.
    if result.headers['Content-Type'] != 'application/xml':
        return False

    root = etree.fromstring(result.text)
    # <?xml> <IPMI> <SSL_INFO> <STATUS>
    validate = root.xpath('//IPMI/SSL_INFO/VALIDATE')
    if not validate:
        return False
    # Since xpath will return a list, just pick the first one from it.
    validate = validate[0]
    cert_idx = validate.get('CERT')
    key_idx = validate.get('KEY')

    return


def upload_cert(session, url, key_file, cert_file):
    """
    Send X.509 certificate and private key to server
    :param session: Current session object
    :type session requests.session
    :param url: base-URL to IPMI
    :param key_file: filename to X.509 certificate private key
    :param cert_file: filename to X.509 certificate PEM
    :return:
    """

    # 1st operation:
    # Upload the X.509 certificate
    with open(key_file, 'rb') as filehandle:
        key_data = filehandle.read()
    with open(cert_file, 'rb') as filehandle:
        cert_data = filehandle.read()
    files_to_upload = [
        ('/tmp/cert.pem', ('cert.cer', cert_data, 'application/x-x509-ca-cert')),
        ('/tmp/key.pem', ('cert.key', key_data, 'application/octet-stream'))
    ]

    request_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        # "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0",
        "Referer": CONFIG_CERT_URL % url,
        "Upgrade-Insecure-Requests": "1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache"
    }

    upload_cert_url = UPLOAD_CERT_URL % url
    try:
        req = requests.Request('POST', upload_cert_url, headers=request_headers, files=files_to_upload)
        prepped = session.prepare_request(req)
        result = session.send(prepped, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False

    if 'Content-Length' not in result.headers.keys() or int(result.headers['Content-Length']) < 400:
        # On failure, a tiny quirks-mode HTML-page will be returned.
        # The page has nothing else, than a JavaScript-check for frames in it.
        print("\nDEBUG, Way too tiny response!")
        return False

    if 'Content-Type' not in result.headers.keys() or result.headers['Content-Type'] != 'text/html':
        # On failure, Content-Type will be 'text/plain' and 'Transfer-Encoding' is 'chunked'
        print("\nDEBUG, Didn't get Content-Type: text/html")
        return False
    if 'CONFPAGE_RESET' not in result.text:
        print("\nDEBUG, Word 'CONFPAGE_RESET' not in result body")
        return False

    # 2nd operation:
    # Validate cert:
    cert_verify = prepare_for_cert_upload(session, url)

    # 3rd operation:
    # Get the uploaded cert stats
    # ... will be done on main()

    return True


def reboot_ipmi(session, url):
    timestamp = datetime.utcnow().strftime('%a %d %b %Y %H:%M:%S GMT')

    reboot_data = {
        'time_stamp': timestamp  # 'Thu Jul 12 2018 19:52:48 GMT+0300 (FLE Daylight Time)'
    }

    upload_cert_url = REBOOT_IPMI_URL % url
    try:
        result = session.post(upload_cert_url, reboot_data, timeout=REQUEST_TIMEOUT, verify=False)
    except ConnectionError:
        return False
    if not result.ok:
        return False

    if '<STATE CODE="OK"/>' not in result.text:
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description='Update Supermicro IPMI SSL certificate')
    parser.add_argument('--ipmi-url', required=True,
                        help='Supermicro IPMI 2.0 URL')
    parser.add_argument('--key-file', required=True,
                        help='X.509 Private key filename')
    parser.add_argument('--cert-file', required=True,
                        help='X.509 Certificate filename')
    parser.add_argument('--username', required=True,
                        help='IPMI username with admin access')
    parser.add_argument('--password', required=True,
                        help='IPMI user password')
    parser.add_argument('--no-reboot', action='store_true',
                        help='The default is to reboot the IPMI after upload for the change to take effect.')
    parser.add_argument('--requests-debug-level', type=int, default=0,
                        help='Debug: Increase requests-library verbosity')
    args = parser.parse_args()

    # Confirm args
    if not os.path.isfile(args.key_file):
        print("--key-file '%s' doesn't exist!" % args.key_file)
        exit(2)
    if not os.path.isfile(args.cert_file):
        print("--cert-file '%s' doesn't exist!" % args.cert_file)
        exit(2)
    if args.ipmi_url[-1] == '/':
        args.ipmi_url = args.ipmi_url[0:-1]

    # XXX
    if args.requests_debug_level == 1:
        # Some logging!
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig(level=logging.DEBUG)
    elif args.requests_debug_level > 1:
        # Max logging!
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    # Start the operation
    # Need to disable server certificate check to overcome any situation where IPMI cert has already expired.
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    session = requests.session()
    if not login(session, args.ipmi_url, args.username, args.password):
        print("Login failed. Cannot continue!")
        exit(2)

    # Set mandatory cookies:
    url_parts = urlparse(args.ipmi_url)
    # Cookie: langSetFlag=0; language=English; SID=<dynamic session ID here!>; mainpage=configuration; subpage=config_ssl
    mandatory_cookies = {
        # Language cookies are set in JavaScript (util.js)
        'langSetFlag': '0',
        'language': 'English',
        # Navigation cookies are set by per-page navigation JavaScript
        'mainpage': 'configuration',
        'subpage': 'config_ssl'
    }
    for cookie_name, cookie_value in mandatory_cookies.items():
        session.cookies.set(cookie_name, cookie_value, domain=url_parts.hostname)

    cert_info = get_ipmi_cert_info(session, args.ipmi_url)
    if not cert_info:
        print("Failed to extract certificate information from IPMI!")
        exit(2)
    if cert_info['has_cert']:
        print("There exists a certificate, which is valid until: %s" % cert_info['valid_until'])
    else:
        print("No existing certificate info. Probably a failure? Continuing.")

    # Go upload!
    if not upload_cert(session, args.ipmi_url, args.key_file, args.cert_file):
        print("Failed to upload X.509 files to IPMI!")
        exit(2)

    print("Uploaded files ok.")

    cert_info = get_ipmi_cert_info(session, args.ipmi_url)
    if not cert_info:
        print("Failed to extract certificate information from IPMI!")
        exit(2)
    if cert_info['has_cert']:
        print("After upload, there exists a certificate, which is valid until: %s" % cert_info['valid_until'])

    if not args.no_reboot:
        print("Rebooting IPMI to apply changes.")
        if not reboot_ipmi(session, args.ipmi_url):
            print("Rebooting failed! Go reboot it manually?")

    print("All done!")


if __name__ == "__main__":
    main()
