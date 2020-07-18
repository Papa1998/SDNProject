"""HTTP over Unix Domain Socket functionality for urllib2.

This function adds a handler to urllib2. To use, import this module and use the
following url style:

    unixhttp://%2Fpath%2Fto%2Fsockfile.sock/url/path

In other words, use unixhttp as your url scheme and use the sockfile as the
host. Furthermore, the path to the sockfile much be 'percent-encoded', 
including the forward slashes in the path. Here is an example:

    import urllib
    import urllib2
    import urllib2_uds

    sockfile = '/path/to/sockfile.sock'
    path = '/url/path'

    url = "unixhttp://" + urllib.quote(sockfile, '') + path

    request = urllib2.Request(url)
    response = urllib2.urlopen(request)
"""

import urllib2
import httplib
import socket

class UnixHTTPConnection(httplib.HTTPConnection):
    def __init__(self, host, **http_connection_args):
        self.sockfile_path = host
        httplib.HTTPConnection.__init__(self, host, **http_connection_args)

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.sockfile_path)
        self.sock = sock

class UnixHTTPHandler(urllib2.AbstractHTTPHandler):
    def unixhttp_open(self, req):

        # using the path to the unix domain socket file as the host
        # in the HTTP header is invalid. The following line overwrites
        # that header with an empty string, leaving the req.host
        # value intact for use in the UnixHTTPConnection instance.
        req.add_unredirected_header('Host', 'localhost')

        return self.do_open(UnixHTTPConnection, req)

    unixhttp_request = urllib2.AbstractHTTPHandler.do_request_

unixhttp_opener = urllib2.build_opener(UnixHTTPHandler)
urllib2.install_opener(unixhttp_opener)
