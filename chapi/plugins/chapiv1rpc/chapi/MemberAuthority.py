import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
from DelegateBase import DelegateBase
from HandlerBase import HandlerBase
from Exceptions import *

ma_logger = amsoil.core.log.getLogger('mav1')
xmlrpc = pm.getService('xmlrpc')

# RPC handler for Member Authority (MA) API calls
class MAv1Handler(HandlerBase):
    def __init__(self):
        super(MAv1Handler, self).__init__(ma_logger)

    # This call is unprotected: no checking of credentials
    # Return version of MA API including object model
    def get_version(self):
        try:
            return self._delegate.get_version()
        except Exception as e:
            return self._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return public information about members specified in options
    # filter and query fields
    def lookup_public_member_info(self, credentials, options):
        try:
            return self._delegate.lookup_public_member_info(credentials, options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Return private information about members specified in options
    # filter and query fields
    # Authorized by client cert and credentials
    def lookup_private_member_info(self, credentials, options):
        client_cert = self.requestCertificate()
        try:
            self._guard.validate(client_cert, 'lookup_private_member_info', \
                                     credentials, options)
            return self._delegate.lookup_private_member_info(client_cert, \
                                                                 credentials, \
                                                                 options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Return identifying information about members specified in options
    # filter and query fields
    # Authorized by client cert and credentials
    def lookup_identifying_member_info(self, credentials, options):
        client_cert = self.requestCertificate()
        self._guard.validate(client_cert, 'lookup_identifying_member_info', \
                                 credentials, options)
        try:
            return self._delegate.lookup_identifying_member_info(client_cert, \
                                                                     credentials, \
                                                                     options)
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Update given member with new data provided in options
    # Authorized by client cert and credentials
    def update_member_info(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        try:
            self._guard.validate(client_cert, 'update_member_info', \
                                     credentials, options, \
                                 {'member_urn' : member_urn})
            return self._delegate.update_member_info(client_cert, member_urn, \
                                                         credentials, options)
        except Exception as e:
            return self._errorReturn(e)


# Base class for implementations of MA API
# Must be  implemented in a derived class, and that derived class
# must call setDelegate on the handler
class MAv1DelegateBase(DelegateBase):

    def __init__(self):
        super(MAv1DelegateBase, self).__init__(ma_logger)
    
    # This call is unprotected: no checking of credentials
    def get_version(self):
        raise CHAPIv1NotImplementedError('')

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, credentials, options):
        print "MAv1DelegateBase.lookup_public_member_info " + \
            "CREDS = %s OPTIONS = %s" % \
            (str(credentials), str(options))
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')



