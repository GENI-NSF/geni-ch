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
    
    # This call is unprotected: no checking of credentials
    # Return version of CH API including object model
    def get_version(self):
        try:
            return self._delegate.get_version()
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
            return self._delegate.get_trust_roots(options)
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

