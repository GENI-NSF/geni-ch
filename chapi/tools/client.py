#----------------------------------------------------------------------
# Copyright (c) 2011-2013 Raytheon BBN Technologies
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
#----------------------------------------------------------------------

import os, os.path, sys
import json
import optparse
from omnilib.util.dossl import _do_ssl
import xmlrpclib
from omnilib.frameworks.framework_base import Framework_Base

# Generic client to speak XMLRPC/SSL SA/CH/MA API calls to 

class MAClientFramework(Framework_Base):
    def __init__(self, config, opts):
        Framework_Base.__init__(self, config)
        self.config = config
        self.logger = None
        self.fwtype = "MA Ciient"
        self.opts = opts

def parseOptions():
    parser = optparse.OptionParser()

    home = os.getenv('HOME')
    gcf_home = os.path.join(home, '.gcf')

    parser.add_option("--url", help="Server URL", default=None)
    parser.add_option("--urn", help="URN for API arguments", default=None)
    parser.add_option("--key", help="Location of user key", \
                          default=os.path.join(gcf_home, 'alice-key.pem'))
    parser.add_option("--cert", help="Location of user cert", \
                          default=os.path.join(gcf_home, 'alice-cert.pem'))
    parser.add_option("--method", help="Name of method to invoke", 
                      default="get_version")
    parser.add_option("--agg_url",  help="URL of aggregate in some API calls",
                      default = None)
    parser.add_option("--options", help="JSON of options argument", default="{}")
    parser.add_option("--options_file", help="File containing JSON of options argument", default=None)
    parser.add_option("--credentials", \
                          help="List of comma-separated credential files", \
                          default="")

    [opts, args] = parser.parse_args(sys.argv)
    if len(opts.credentials) > 0:
        credentials = "".join(opts.credentials.split())
        credentials = credentials.split(',')
        opts.credentials = credentials
    else:
        opts.credentials = []

    if opts.url == None:
        raise Exception("URL is required argument")

    return opts, args

def main():

    opts, args = parseOptions()
    client_options = json.loads(opts.options)
    if opts.options_file:
        client_options = json.load(open(opts.options_file, 'r'))
    print "CREDS = " + str(opts.credentials)
    print "OPTIONS = " + str(client_options)
    suppress_errors = None
    reason = "Testing"
    config = {'cert' : opts.cert, 'key' : opts.key}

    framework = MAClientFramework(config, {})
    client = framework.make_client(opts.url, opts.key, opts.cert, verbose=False)
    fcn = eval("client.%s" % opts.method)
    
    # Methods that take no arguments
    result = None
    msg = None

    if opts.method in ['get_version', 'get_trust_roots']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn)
    # Methods that take options argument
    elif opts.method in ['get_member_authorities', 'get_slice_authorities', \
                             'get_aggregates', \
                             'lookup_authorities_for_urns' ]:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn, \
                                    client_options)
    # Methods that take a URN and an aggregate URL argument
    elif opts.method in ['register_aggregate', 'remove_aggregate'] and opts.agg_url:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn, \
                                    opts.urn, opts.agg_url, opts.credentials, client_options)
    # Methods that take credentials and options and urn arguments
    elif opts.urn:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn, \
                                    opts.urn, \
                                    opts.credentials, client_options)
    # Methods that take credentials and options (and no urn) arguments
    else:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn, \
                                    opts.credentials, client_options)

    print "RESULT = " + str(result)
    print "MSG = " + str(msg)
    
if __name__ == "__main__":
    sys.exit(main())
