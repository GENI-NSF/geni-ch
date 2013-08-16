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

class PGCHClientFramework(Framework_Base):
    def __init__(self, config, opts):
        Framework_Base.__init__(self, config)
        self.config = config
        self.logger = None
        self.fwtype = "PGCH Ciient"
        self.opts = opts

def parseOptions():
    parser = optparse.OptionParser()

    home = os.getenv('HOME')
    gcf_home = os.path.join(home, '.gcf')

    parser.add_option("--url", help="Server URL", default=None)
    parser.add_option("--key", help="Location of user key", \
                          default=os.path.join(gcf_home, 'alice-key.pem'))
    parser.add_option("--cert", help="Location of user cert", \
                          default=os.path.join(gcf_home, 'alice-cert.pem'))
    parser.add_option("--method", help="Name of method to invoke", 
                      default="get_version")
    parser.add_option("--args", help="JSON of args argument", default=None)
    parser.add_option("--args_file", help="File containing JSON of args argument", default=None)

    [opts, args] = parser.parse_args(sys.argv)

    return opts, args

def main():

    opts, args = parseOptions()
    client_args = {}
    if opts.args:
        client_args = json.loads(opts.args)
    if opts.args_file:
        client_args = json.load(open(opts.args_file, 'r'))
    print "METHOD = " + opts.method + " ARGS = " + str(client_args)
    suppress_errors = None
    reason = "Testing"
    config = {'cert' : opts.cert, 'key' : opts.key}

    framework = PGCHClientFramework(config, {})
    client = framework.make_client(opts.url, opts.key, opts.cert, verbose=False)
    fcn = eval("client.%s" % opts.method)
    
    # Methods that take no arguments
    result = None
    msg = None

    if opts.method == 'GetVersion':
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn)
    else:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, \
                                    fcn, client_args)

    print "RESULT = " + str(result)
    if msg:
        print "MSG = " + str(msg)
    
if __name__ == "__main__":
    sys.exit(main())
