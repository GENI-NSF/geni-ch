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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
from DelegateBase import DelegateBase
from HandlerBase import HandlerBase
from Exceptions import *

ch_logger = amsoil.core.log.getLogger('chv1')
xmlrpc = pm.getService('xmlrpc')

# RPC handler for Clearinghouse API calls
class CHv1Handler(HandlerBase):
    def __init__(self):
        super(CHv1Handler, self).__init__(ch_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        chapi_log_exception(SR_LOG_PREFIX, e)
        return super(MAv1Handler, self)._errorReturn(e)
    
    # This call is unprotected: no checking of credentials
    # Return version of CH API including object model
    def get_version(self):
        try:
            gv_return = self._delegate.get_version()
#            print "GV_RETURN = " + str(gv_return)
            return gv_return
        except Exception as e:
            return self._errorReturn(e)
    
    # This call is unprotected: no checking of credentials
    # Return list of member authorities with matching and filter criteria
    # specified in options
    def get_member_authorities(self, options):
        try:
            return self._delegate.get_member_authorities(options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return list of slice authorities with matching and filter criteria
    # specified in options
    def get_slice_authorities(self, options):
        try:
            return self._delegate.get_slice_authorities(options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return list of aggregates with matching and filter criteria`
    # specified in options
    def get_aggregates(self, options):
        try:
            return self._delegate.get_aggregates(options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return URL of authority (slice or member) for given URN
    def lookup_authorities_for_urns(self, options):
        try:
            return self._delegate.lookup_authorities_for_urns(options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return list of trust roots trusted by authorities and aggregates of
    # the federation associated with this Clearinghouse
    def get_trust_roots(self):
        try:
            return self._delegate.get_trust_roots()
        except Exception as e:
            return self._errorReturn(e)

# Base class for implementations of CH API
# Must be  implemented in a derived class, and that derived class
# must call setDelegate on the handler
class CHv1DelegateBase(DelegateBase):
    
    def __init__(self):
        super(CHv1DelegateBase, self).__init__(ch_logger)
    
    def get_version(self):
        raise CHAPIv1NotImplementedError('')

    def get_member_authorities(self, options):
        raise CHAPIv1NotImplementedError('')


    def get_slice_authorities(self, options):
        raise CHAPIv1NotImplementedError('')

    def get_aggregates(self, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_authorities_for_urns(self, options):
        raise CHAPIv1NotImplementedError('')

    def get_trust_roots(self):
        raise CHAPIv1NotImplementedError('')

