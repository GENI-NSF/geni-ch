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
from tools.cert_utils import *
from tools.chapi_log import *
from MethodContext import *

ma_logger = amsoil.core.log.getLogger('mav1')
xmlrpc = pm.getService('xmlrpc')

# RPC handler for Member Authority (MA) API calls
class MAv1Handler(HandlerBase):
    def __init__(self):
        super(MAv1Handler, self).__init__(ma_logger)

    def get_version(self):
        """Return version of MA API including object model
        This call is unprotected: no checking of credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 'get_version',
                           {}, [], {}, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_version(mc._session)
        return mc._result

    # MEMBER service methods
    def lookup_public_member_info(self, credentials, options):
        """Return public information about members specified in options
        filter and query fields
        
        This call is unprotected: no checking of credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 'lookup_public_member_info', 
                           {}, credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_public_member_info(mc._client_cert, 
                                                             credentials, 
                                                             options,
                                                             mc._session)
        return mc._result

    def lookup_private_member_info(self, credentials, options):
        """Return private information about members specified in options
        filter and query fields

        This call is protected
        Authorized by client cert and credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 'lookup_private_member_info', 
                           {}, credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_private_member_info(mc._client_cert, 
                                                              credentials, 
                                                              options,
                                                              mc._session)
        return mc._result

    def lookup_identifying_member_info(self, credentials, options):
        """Return identifying information about members specified in options
        filter and query fields
        
        This call is protected
        Authorized by client cert and credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'lookup_identifying_member_info', 
                           {}, credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_identifying_member_info(mc._client_cert, 
                                                                  credentials, 
                                                                  options,
                                                                  mc._session)
        return mc._result

    def get_credentials(self, member_urn, credentials, options):
        """Get credentials for given user
        
        This call is protected
        Authorization based on client cert and given credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'get_credentials', 
                           {'member_urn' : member_urn}, 
                           credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_credentials(mc._client_cert, 
                                                   member_urn, 
                                                   credentials, 
                                                   options,
                                                   mc._session)
        return mc._result

    def update_member_info(self, member_urn, credentials, options):
        """Update given member with new data provided in options
        
        This call is protected
        Authorized by client cert and credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'update_member_info', 
                           {'member_urn' : member_urn},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.update_member_info(mc._client_cert, 
                                                      member_urn,
                                                      credentials, 
                                                      options,
                                                      mc._session)
        return mc._result

    def create_member(self, attributes, credentials, options):
        """Create a new member using the specified attributes.  Attribute email is 
        required.  Returns the attributes of the resulting member record, including
        the uid and urn.
        
        This call is protected
        Authorized by client cert and credentials
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'create_member',
                           {'attributes' : attributes}, 
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.create_member(mc._client_cert, 
                                                 attributes,
                                                 credentials, 
                                                 options,
                                                 mc._session)
        return mc._result

    # KEY service methods

    def create_key(self, credentials, options):
        """Create a record for a key pair for given member
        Arguments:
            member_urn: URN of member for which to retrieve credentials
            options: 'fields' containing the fields for the key pair being stored
        Return:
            Dictionary of name/value pairs for created key record 
            including the KEY_ID
       Should return DUPLICATE_ERROR if a key with the same KEY_ID is 
       already stored for given user
       """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'create_key', 
                           {}, credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.create_key(mc._client_cert, 
                                              credentials, 
                                              options,
                                              mc._session)
        return mc._result

    def delete_key(self, member_urn, key_id, credentials, options):
        """Delete a key pair for given member
        Arguments:
            member_urn: urn of member for which to delete key pair
            key_id: KEY_ID (fingerprint) of key pair to be deleted
        Return:
            True if succeeded
            
        Should return ARGUMENT_ERROR if no such key is found for user
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'delete_key', 
                           {'member_urn' : member_urn, 'key_id' : key_id}, 
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.delete_key(mc._client_cert, 
                                              member_urn,
                                              key_id,
                                              credentials, 
                                              options,
                                              mc._session)
        return mc._result

    def update_key(self, member_urn, key_id, credentials, options):
        """
        Update the details of a key pair for given member
        
        Arguments:
          member_urn: urn of member for which to delete key pair
          key_id: KEY_ID (fingerprint) of key pair to be deleted
          options: 'fields' containing fields for key pairs that are permitted 
        for update
        Return:
            True if succeeded
        Should return ARGUMENT_ERROR if no such key is found for user
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'update_key', 
                           {'member_urn' : member_urn, 'key_id' : key_id}, 
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.update_key(mc._client_cert, 
                                              member_urn, key_id,
                                              credentials, 
                                              options,
                                              mc._session)
        return mc._result

    def lookup_keys(self, credentials, options):
        """Lookup keys for given match criteria return fields in given 
        #  filter criteria
        #
        # Arguments:
        # options: 'match' for query match criteria, 'filter' for fields 
        #    to be returned
        # Return:
        #  Dictionary (indexed by member_urn) of dictionaries containing 
        #     name/value pairs for all keys registered for that given user.
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'lookup_keys_keys', 
                           {}, credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.lookup_keys(mc._client_cert, 
                                              credentials, 
                                              options,
                                              mc._session)
        return mc._result

    def create_certificate(self, member_urn, credentials, options):
        """Methods for managing user certs
        # options: 
        # 'csr' => certificate signing request (if null, create cert/key)
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'create_certificate', 
                           {'member_urn' : member_urn}, 
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.create_certificate(mc._client_cert, 
                                              member_urn,
                                              credentials, 
                                              options,
                                              mc._session)
        return mc._result

    # ClientAuth API
    def list_clients(self):
        """
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'list_clients', 
                           {}, [], {}, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.list_clients(mc._session)
        return mc._result

    def list_authorized_clients(self, member_id):
        """
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'list_authorized_clients', 
                           {'member_id' : member_id}, [], {}, 
                           read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.list_authorized_clients(mc._client_cert,
                                                           member_id,
                                                           mc._session)
        return mc._result

    def authorize_client(self, member_id, client_urn, authorize_sense):
        """
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'authorized_client', 
                           {'member_id' : member_id,'client_urn' : client_urn},
                           [], {}, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.list_authorized_client(mc._client_cert,
                                                          member_id,
                                                          client_urn,
                                                          mc._session)
        return mc._result


    # member disable API
    def enable_user(self, member_urn, enable_sense, credentials, options):
        """Enable or disable a user based on URN. If enable_sense is False, then user 
        will be disabled.
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'enable_user', 
                           {'member_urn' : member_urn,
                            'enable_sense' : enable_sense},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.list_authorized_clients(mc._client_cert,
                                                           member_urn,
                                                           enable_sense,
                                                           credentials,
                                                           options,
                                                           mc._session)
        return mc._result

    # member privilege (private)
    def add_member_privilege(self, member_uid, privilege, credentials, options):
        """Add a privilege to a member.
        privilege is either OPERATOR or PROJECT_LEAD
        """
        with MethodContext(self, MA_LOG_PREFIX, 
                           'add_member_privilege', 
                           {'member_uid' : member_uid,'privilege' : privilege},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.add_member_privilege(mc._client_cert,
                                                        member_uid,
                                                        privilege,
                                                        credentials,
                                                        options,
                                                        mc._session)
        return mc._result

    def revoke_member_privilege(self, member_uid, privilege, credentials, options):
        """Revoke a privilege for a member."""
        with MethodContext(self, MA_LOG_PREFIX, 
                           'revoke_member_privilege', 
                           {'member_uid' : member_uid,'privilege' : privilege},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.revoke_member_privilege(mc._client_cert,
                                                           member_uid,
                                                           privilege,
                                                           credentials,
                                                           options,
                                                           mc._session)
        return mc._result

    def add_member_attribute(self,
                             member_urn, name, value, self_asserted,
                             credentials, options):
        """Add an attribute to member"""
        with MethodContext(self, MA_LOG_PREFIX, 
                           'add_member_attribute', 
                           {'member_urn' : member_urn, 
                            'name' : name, 'value' : value, 
                            'self_asserted' : self_asserted},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.add_member_attribute(mc._client_cert,
                                                        member_urn,
                                                        name, 
                                                        value,
                                                        self_asserted,
                                                        credentials,
                                                        options,
                                                        mc._session)
        return mc._result

    def remove_member_attribute(self, 
                                member_urn, name,
                                credentials, options, value=None):
        """Remove attribute to member"""
        with MethodContext(self, MA_LOG_PREFIX, 
                           'remove_member_attribute', 
                           {'member_urn' : member_urn, 'name' : name, 
                            'value' : value},
                           credentials, options, read_only=False) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.remove_member_attribute(mc._client_cert,
                                                        member_urn,
                                                        name, 
                                                        credentials,
                                                        options,
                                                        mc._session, value)
        return mc._result


# Base class for implementations of MA API
# Must be  implemented in a derived class, and that derived class
# must call setDelegate on the handler
class MAv1DelegateBase(DelegateBase):

    def __init__(self):
        super(MAv1DelegateBase, self).__init__(ma_logger)
    
    # This call is unprotected: no checking of credentials
    def get_version(self):
        raise CHAPIv1NotImplementedError('')

    # MEMBER service methods

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, client_cert, 
                                  credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_private_member_info(self, client_cert, 
                                   credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, 
                                       credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def get_credentials(self, client_cert, member_urn, 
                        credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def update_member_info(self, client_cert, member_urn, 
                           credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def create_member(self, client_cert, attributes, 
                      credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # KEY service methods

    def create_key(self, client_cert, credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def delete_key(self, client_cert, member_urn, key_id, 
                   credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def update_key(self, client_cert, member_urn, key_id, 
                   credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def lookup_keys(self, client_cert, credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # Member certificate methods
    def create_certificate(self, client_cert, member_urn, \
                               credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    # ClientAuth methods
    def list_clients(self, session):
        raise CHAPIv1NotImplementedError('')

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id, session):
        raise CHAPIv1NotImplementedError('')

    # Authorize/deauthorize a tool with respect to a user
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense, session):
        raise CHAPIv1NotImplementedError('')

    # Private API
    def enable_user(self, client_cert, member_urn, enable_sense, 
                    credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def add_member_privilege(self, client_cert, member_uid, privilege,
                             credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def revoke_member_privilege(self, client_cert, member_uid, privilege,
                                credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def add_member_attribute(self, client_cert, member_urn, att_name, 
                             att_value, att_self_asserted, 
                             credentials, options, session):
        raise CHAPIv1NotImplementedError('')

    def remove_member_attribute(self, client_cert, member_urn, att_name, \
                                    credentials, options, session, att_value=None):
        raise CHAPIv1NotImplementedError('')
