# ----------------------------------------------------------------------
# Copyright (c) 2011-2017 Raytheon BBN Technologies
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

# This gets called when we invoke any of the CH methods

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

from tools.chapi_log import *


def initialize():
    pm.registerService('xmlrpc', pm.XMLRPCHandler())
    pm.registerService('config', pm.ConfigDB())
    pm.registerService('rpcserver', pm.RESTServer())
    pm.registerService(pm.ENVIRONMENT_SERVICE, pm.WSGIEnvironment())
    plugins.chapiv1rpc.plugin.setup()
    plugins.chrm.plugin.setup()
    plugins.csrm.plugin.setup()
    plugins.flaskrest.plugin.setup()
    plugins.logging.plugin.setup()
    plugins.opsmon.plugin.setup()
    plugins.marm.plugin.setup()
    plugins.sarm.plugin.setup()
    chapi_info("CH_SERVER", "INITIALIZED CH_SERVER")


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    try:
        result = handleCall(environ)
        return [result]
    except Exception as e:
        msg = "%s: %s" % (type(e).__name__, str(e))
        fault = xmlrpclib.Fault(1, msg)
        response = xmlrpclib.dumps(fault, methodresponse=True, allow_none=True)
        return [response]


def handleCall(environ):
    # Try to handle REST invocations, registered with rpcserver
    rest_output = handle_REST_call(environ)
    if rest_output:
        # It is a REST invocation
        return rest_output
    else:
        # Otherwise it is an XMLRPC invocation
        xmlrpc_output = handle_XMLRPC_call(environ)
        return xmlrpc_output


# Handle XMLRPC invocation
def handle_XMLRPC_call(environ):

    xmlrpc_endpoint = environ['REQUEST_URI']
    xmlrpc = pm.getService('xmlrpc')
    handler_entry = xmlrpc.lookupByEndpoint(xmlrpc_endpoint)
    handler = handler_entry._instance

    length = int(environ['CONTENT_LENGTH'])
    wsgi_input = environ['wsgi.input']
    data = wsgi_input.read(length)
    decoded_data = xmlrpclib.loads(data)

    args = decoded_data[0]
    method = decoded_data[1]
    fcn = getattr(handler, method)

    envService = pm.getService(pm.ENVIRONMENT_SERVICE)
    envService.setEnvironment(environ)
    try:
        method_response = fcn(*args)
        # print "RESPONSE = %r" % (method_response)
    finally:
        # Always clear the environment after the call is complete,
        # even if there was an exception
        envService.clearEnvironment()
    response = xmlrpclib.dumps((method_response,),
                               methodresponse=True, allow_none=True)
    return response


# Determine if this is a REST call. If so, make the call and return output
def handle_REST_call(environ):
    if 'PATH_INFO' in environ:
        path_info = environ['PATH_INFO']
        rpcserver = pm.getService('rpcserver')
        handler = rpcserver.app.lookup_handler(path_info)
        if handler:
            pieces = path_info.split('/')
            if len(pieces) < 4:
                return None
            variety = pieces[2]
            id = pieces[3]
            output = handler(variety, id)
            return output
        return None
