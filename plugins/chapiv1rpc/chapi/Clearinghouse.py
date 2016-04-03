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

import logging
import tools.pluginmanager as pm
from DelegateBase import DelegateBase
from HandlerBase import HandlerBase
from Exceptions import *
from tools.cert_utils import *
from tools.chapi_log import *
from MethodContext import *
import tools.CH_constants as CH

ch_logger = logging.getLogger('chv1')

# RPC handler for Clearinghouse API calls
class CHv1Handler(HandlerBase):
    def __init__(self):
        super(CHv1Handler, self).__init__(ch_logger)

    # This call is unprotected: no checking of credentials
    # Return version of CH API including object model
    def get_version(self, options={}):
        with MethodContext(self, SR_LOG_PREFIX, 'get_version',
                           {}, [], options, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_version(options, mc._session)
        return mc._result
    
    # This call is unprotected: no checking of credentials
    # Return list of member authorities with matching and filter criteria
    # specified in options
    def lookup_member_authorities(self, options):
        with MethodContext(self, SR_LOG_PREFIX, 'lookup_member_authorities', 
                           {}, [], options, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_member_authorities( mc._client_cert,
                                                              options,
                                                              mc._session)
        return mc._result

    # This call is unprotected: no checking of credentials
    # Return list of slice authorities with matching and filter criteria
    # specified in options
    def lookup_slice_authorities(self, options):
        with MethodContext(self, SR_LOG_PREFIX, 'lookup_slice_authorities', 
                           {}, [], options, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_slice_authorities(mc._client_cert,
                                                            options,
                                                            mc._session)
        return mc._result

    # This call is unprotected: no checking of credentials
    # Return list of aggregates with matching and filter criteria`
    # specified in options
    def lookup_aggregates(self, options):
         with MethodContext(self, SR_LOG_PREFIX, 'lookup_aggregates', 
                           {}, [], options, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_aggregates(mc._client_cert,
                                                     options,
                                                     mc._session)
         return mc._result

    # Generic v2 lookup method for services
    def lookup(self, type, credentials, options):
        with MethodContext(self, SR_LOG_PREFIX, 'lookup',
                           {}, [], options, read_only=True, cert_required=False) as mc:
            if type not in CH.services:
                raise CHAPIv1ArgumentError("Invalid type: %s" % type)
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_services(mc._client_cert, options, mc._session)
        return mc._result

    # This call is unprotected: no checking of credentials
    # Return URL of authority (slice or member) for given URN
    def lookup_authorities_for_urns(self, urns):
         with MethodContext(self, SR_LOG_PREFIX, 
                            'lookup_authorities_for_urns', 
                           {'urns' : urns}, [], {}, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_authorities__for_urns(mc._client_cert, 
                                                                urns,
                                                                mc._session)
         return mc._result

    # This call is unprotected: no checking of credentials
    # Return list of trust roots trusted by authorities and aggregates of
    # the federation associated with this Clearinghouse
    def get_trust_roots(self):
         with MethodContext(self, SR_LOG_PREFIX, 
                            'get_trust_roots',
                           {}, [], {}, read_only=True, cert_required=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_trust_roots(mc._client_cert, 
                                                   mc._session)
         return mc._result

# Base class for implementations of CH API
# Must be  implemented in a derived class, and that derived class
# must call setDelegate on the handler
class CHv1DelegateBase(DelegateBase):
    
    def __init__(self):
        super(CHv1DelegateBase, self).__init__(ch_logger)
    
    def get_version(self, options, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_member_authorities(self, client_cert, options, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_slice_authorities(self, client_cert, options, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_aggregates(self, client_cert, options, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_authorities_for_urns(self, client_cert, urns, session):
        raise CHAPIv1NotImplementedError('')

    def get_trust_roots(self, client_cert, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_services(self, client_cert, options, session):
        raise CHAPIv1NotImplementedError('')
        

