#----------------------------------------------------------------------
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
#----------------------------------------------------------------------

import threading
import wsgiref.util

# A set of classes to replace services provided by AMsoil.
# Simplified to support only use cases needed by GENI Clearinghouse

ENVIRONMENT_SERVICE = 'environment'

# All XMLRPC services registered
ALL_SERVICES = {}

def registerService(name, service):
    ALL_SERVICES[name] = service

def getService(name):
    return ALL_SERVICES[name]

# Stored in plugin manager as 'xmlrpc' service
# Manages link between registered end points and handlers
class XMLRPCHandler(object):

    _entries = []
    _entries_by_endpoint = {}
    _entries_by_service_name = {}

    def registerXMLRPC(self, unique_service_name, instance, endpoint):
        entry = XMLRPCEntry(unique_service_name, instance, endpoint)
        self._entries.append(entry)
        self._entries_by_endpoint[endpoint] = entry
        self._entries_by_service_name[unique_service_name] = entry

    def lookupByEndpoint(self, endpoint):
        return self._entries_by_endpoint[endpoint]

    def lookupByServiceName(self, service_name):
        return self._entries_by_service_name[service_name]

# An XMLRPC entry: the service name, handler, endpoint
class XMLRPCEntry(object):
    def __init__(self, unique_service_name, instance, endpoint):
        self._unique_service_name = unique_service_name
        self._instance = instance
        self._endpoint = endpoint

# Stored in plugin manager as 'config' service
# Maintains a list of mappings of keys to values
class ConfigDB(object):
    _mapping = {}

    def install(self, key, defaultValue, defaultDescription, force=False):
#        print "ConfigDB.install %s %s %s %s" % \
#            (key, defaultValue, defaultDescription, force)
        # ***
        pass

    def set(self, key, value):
        self._mapping[key] = value
        
    def get(self, key):
        return self._mapping[key]

    def getAll(self):
        return self._mapping.keys()

# An entry registering a REST service: 
#    endpoint and handler are all we really care about
class RESTEntry(object):
    def __init__(self, endpoint, rule, handler, defaults, methods):
        self._endpoint = endpoint
        self._rule = rule
        self._handler = handler
        self._defaults = defaults
        self._methods = methods

# Dispatcher for REST calls, based on 
class RESTDispatcher(object):
    _entries_by_endpoint = {}

    # Register a dispatch rule mapping key (first entry) to handler
    def add_url_rule(self, endpoint, rule, handler, defaults, methods):
#        print "RESTDispatcher called: %s %s %s %s %s" % \
#            (endpoint, rule, handler, defaults, methods)
        entry = RESTEntry(endpoint, rule, handler, defaults, methods)
        #  /foo/bar/baz ==> foo as key
        key = endpoint.split('/')[1]
        self._entries_by_endpoint[key] = entry

    # Lookup handler for given endpoint (/foo/bar/baz => key = foo)
    def lookup_handler(self, endpoint):
        pieces = endpoint.split('/')
        if len(pieces) > 2:
            key = endpoint.split('/')[1]
        
            if key in self._entries_by_endpoint:
                return self._entries_by_endpoint[key]._handler
        return None

# The REST server really just delegates to a dispatcher
class RESTServer(object):

    app = RESTDispatcher()


class WSGIEnvironment(object):
    """Environment Service to hold environment for call context. Stored
    in the PluginManager as ENVIRONMENT_SERVICE. Holds the full WSGI
    environment but only makes available the client certificate and the
    server URL. Could make other things available in the future.
    """

    _thread_local = threading.local()

    def setEnvironment(self, environ):
        self._thread_local.environ = environ

    def clearEnvironment(self):
        self._thread_local.__dict__.clear()

    def getClientCertificate(self):
        # TODO: error checking
        return self._thread_local.environ['SSL_CLIENT_CERT']

    def getServerURL(self):
        include_query = False
        return wsgiref.util.request_uri(self._thread_local.environ,
                                        include_query)
