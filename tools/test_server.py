#!/usr/bin/env python
# ----------------------------------------------------------------------
# Copyright (c) 2011-2016 Raytheon BBN Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and/or hardware specification (the "Work") to
# deal in the Work without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Work, and to permit persons to whom the Work
# is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Work.
#
# THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
# IN THE WORK.
# ----------------------------------------------------------------------

# A CH server providing a single-threaded one-at-a-time service that responds
# to CH API XMLRPC/SSL requests.

# Note: Need to place a /etc/geni-chapi/chapi-dev.ini containing an entry:
#   ; database URL
#   ;  Syntax: postgresql://USER:PASSWORD@HOST/DB
#

from gcf.geni.SecureXMLRPCServer import SecureXMLRPCRequestHandler
from gcf.geni.SecureXMLRPCServer import SecureXMLRPCServer

import optparse
import os
import sys
import urlparse
import xmlrpclib

import tools.pluginmanager as pm
import plugins.chapiv1rpc.plugin
import plugins.chrm.plugin
import plugins.csrm.plugin
import plugins.flaskrest.plugin
import plugins.logging.plugin
import plugins.opsmon.plugin
import plugins.marm.plugin
import plugins.sarm.plugin

from plugins.chapiv1rpc.chapi.Parameters import set_auxiliary_config_file

from tools.chapi_log import *
from tools.ch_server import handleCall, initialize

opts = None
args = None
test_server_initialized = False

# This server overrides certain parameters (notably the database)
# in a subsequently parsed parameters config file.
set_auxiliary_config_file('chapi-test.ini')

pm.registerService('xmlrpc', pm.XMLRPCHandler())
pm.registerService('config', pm.ConfigDB())
pm.registerService('rpcserver', pm.RESTServer())
pm.registerService(pm.ENVIRONMENT_SERVICE, pm.WSGIEnvironment())


class MySecureXMLRPCRequestHandler(SecureXMLRPCRequestHandler):

    def __init__(self, request, client_address, server):
        SecureXMLRPCRequestHandler.__init__(self, request,
                                            client_address, server)

    def do_POST(self):

        # Set up environment to be compatible with WSGI application environment
        environ = {}
        environ['CONTENT_LENGTH'] = self.headers.getheader('content-length', 0)
        environ['wsgi.input'] = self.rfile
        environ['wsgi.url_scheme'] = 'https'
        sockname = self.request.getsockname()
        environ['SERVER_NAME'] = sockname[0]
        environ['SERVER_PORT'] = str(sockname[1])
        environ['REQUEST_URI'] = self.path
        environ['SSL_CLIENT_CERT'] = self.server.pem_cert
        environ['PATH_INFO'] = self.path

        try:
            response = handleCall(environ)
        except Exception as e:
            msg = "%s: %s" % (type(e).__name__, str(e))
            fault = xmlrpclib.Fault(1, msg)
            response = xmlrpclib.dumps(fault, methodresponse=True,
                                       allow_none=True)

        self.wfile.write(response)
        self.wfile.flush()
        self.connection.shutdown(1)


def parseOptions():
    parser = optparse.OptionParser()

    parser.add_option("--hostname", help="Server hostname/IP",
                      default="localhost")
    parser.add_option("--port", help="Server TCP Port", default="9999")
    default = '/usr/share/geni-ch/portal/gcf.d/trusted_roots/CATedCACerts.pem'
    parser.add_option("--trusted_roots",
                      help="Concatenated set of trusted X509 certs",
                      default=default)
    parser.add_option("--cert_file", help="Server certificate",
                      default="/usr/share/geni-ch/ma/ma-cert.pem")
    parser.add_option("--key_file", help="Server private key",
                      default="/usr/share/geni-ch/ma/ma-key.pem")

    return parser.parse_args(sys.argv)


def main():
    global opts, args
    opts, args = parseOptions()

    initialize()

    server = SecureXMLRPCServer((opts.hostname, int(opts.port)),
                                requestHandler=MySecureXMLRPCRequestHandler,
                                ca_certs=opts.trusted_roots,
                                keyfile=opts.key_file,
                                certfile=opts.cert_file)
    print "Serving on %s:%d" % (opts.hostname, int(opts.port))
    server.serve_forever()


if __name__ == "__main__":
    main()
