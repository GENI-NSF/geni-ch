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
from tools.chapi_log import *

ma_logger = amsoil.core.log.getLogger('mav1')
xmlrpc = pm.getService('xmlrpc')

# RPC handler for Member Authority (MA) API calls
class MAv1Handler(HandlerBase):
    def __init__(self):
        super(MAv1Handler, self).__init__(ma_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        chapi_log_exception(MA_LOG_PREFIX, e)
        return super(MAv1Handler, self)._errorReturn(e)

    # This call is unprotected: no checking of credentials
    # Return version of MA API including object model
    def get_version(self):
        try:
            return self._delegate.get_version()
        except Exception as e:
            return self._errorReturn(e)

    # MEMBER service methods

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
        method = 'lookup_private_member_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            results = self._delegate.lookup_private_member_info(client_cert, \
                                                                    credentials, \
                                                                    options)

            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results

        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Return identifying information about members specified in options
    # filter and query fields
    # Authorized by client cert and credentials
    def lookup_identifying_member_info(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_identifying_member_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            results = self._delegate.lookup_identifying_member_info(client_cert, \
                                                                        credentials, \
                                                                        options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results

        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Update given member with new data provided in options
    # Authorized by client cert and credentials
    def update_member_info(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'update_member_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method,
                                          credentials, options, \
                                          {'member_urn' : member_urn})
            results = self._delegate.update_member_info(client_cert, member_urn, \
                                                            credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Create a new member using the specified attributes.  Attribute email is 
    # required.  Returns the attributes of the resulting member record, including
    # the uid and urn.
    # Authorized by client cert and credentials
    def create_member(self, attributes, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_member'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'attributes' : attributes})
            results =  self._delegate.create_member(client_cert, \
                                                    attributes, \
                                                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results

        except Exception as e:
            return self._errorReturn(e)

    # KEY service methods

    # Create a record for a key pair for given member
    # Arguments:
    # member_urn: URN of member for which to retrieve credentials
    # options: 'fields' containing the fields for the key pair being stored
    # Return:
    # Dictionary of name/value pairs for created key record 
    #   including the KEY_ID
    # Should return DUPLICATE_ERROR if a key with the same KEY_ID is 
    #  already stored for given user
    def create_key(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_key'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method,
                                      credentials, options, \
                                          {'member_urn' : member_urn})
            results = self._delegate.create_key(client_cert, member_urn, \
                                                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)
                
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Delete a key pair for given member
    #
    # Arguments:
    # member_urn: urn of member for which to delete key pair
    # key_id: KEY_ID (fingerprint) of key pair to be deleted
    # Return:
    # True if succeeded
    # Should return ARGUMENT_ERROR if no such key is found for user
    def delete_key(self, member_urn, key_id, credentials, options):
        client_cert = self.requestCertificate()
        method = 'delete_key'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method,
                                      credentials, options, \
                                          {'member_urn' : member_urn, 
                                           'key_id' : key_id})
            results = self._delegate.delete_key(client_cert, member_urn, \
                                                    key_id, \
                                                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)
                
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Update the details of a key pair for given member
    #
    # Arguments:
    # member_urn: urn of member for which to delete key pair
    # key_id: KEY_ID (fingerprint) of key pair to be deleted
    # options: 'fields' containing fields for key pairs that are permitted 
    #   for update
    # Return:
    # True if succeeded
    # Should return ARGUMENT_ERROR if no such key is found for user
    def update_key(self, member_urn, key_id, credentials, options):
        client_cert = self.requestCertificate()
        method = 'update_key'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method,
                                      credentials, options, \
                                          {'member_urn' : member_urn,
                                           'key_id' : key_id})
            results = self._delegate.update_key(client_cert, member_urn, \
                                                    key_id, \
                                                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)
                
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup keys for given match criteria return fields in given 
    #  filter criteria
    #
    # Arguments:
    # options: 'match' for query match criteria, 'filter' for fields 
    #    to be returned
    # Return:
    #  Dictionary (indexed by member_urn) of dictionaries containing 
    #     name/value pairs for all keys registered for that given user.
    def lookup_keys(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_keys'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method,
                                      credentials, options)
            results = self._delegate.lookup_keys(client_cert, \
                                                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)
                
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Methods for managing user certs
    # options: 
    # 'csr' => certificate signing request (if null, create cert/key)
    def create_certificate(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_certificate'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_urn': member_urn})
            results = self._delegate.create_certificate(client_cert, \
                                                            member_urn, 
                                                            credentials, \
                                                            options)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # ClientAuth API
    def list_clients(self):
        try:
            return self._delegate.list_clients()
        except Exception as e:
            return self._errorReturn(e)

    def list_authorized_clients(self, member_id):
        method = 'list_authorized_clients'
        client_cert = self.requestCertificate()
        try:
            self._guard.validate_call(client_cert, method, \
                                          [], {}, {'member_id': member_id})
            results = self._delegate.list_authorized_clients(client_cert, \
                                                                 member_id)
            return results;
        except Exception as e:
            return self._errorReturn(e)

    def authorize_client(self, member_id, client_urn, authorize_sense):
        method = 'authorize_client'
        client_cert = self.requestCertificate()
        try:
            self._guard.validate_call(client_cert, method, [], {}, \
                                          {'member_id' : member_id, \
                                               'client_urn' : client_urn})
            results = self._delegate.authorize_client(client_cert, \
                                                           member_id, \
                                                           client_urn, \
                                                           authorize_sense)
            return results;
        except Exception as e:
            return self._errorReturn(e)

    # member disable API
    def enable_user(self, member_urn, enable_sense, credentials, options):
        client_cert = self.requestCertificate()
        method = 'enable_user'
        try:
            self._guard.validate_call(client_cert, method,
                                      credentials, options,
                                      {'member_urn': member_urn})
            client_cert, options = self._guard.adjust_client_identity(
                client_cert, credentials, options)
            results = self._delegate.enable_user(client_cert,
                                                 member_urn, 
                                                 enable_sense,
                                                 credentials,
                                                 options)
            return results
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

    # MEMBER service methods

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, credentials, options):
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

    # This call is protected
    def create_member(self, client_cert, attributes, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # KEY service methods

    def create_key(self, client_cert, member_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def delete_key(self, client_cert, member_urn, key_id, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def update_key(self, client_cert, member_urn, key_id, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_keys(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # Member certificate methods
    def create_certificate(self, client_cert, member_urn, \
                               credentials, options):
        raise CHAPIv1NotImplementedError('')

    # ClientAuth methods
    def list_clients(self):
        raise CHAPIv1NotImplementedError('')

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id):
        raise CHAPIv1NotImplementedError('')

    # Authorize/deauthorize a tool with respect to a user
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense):
        raise CHAPIv1NotImplementedError('')


    def enable_user(self, client_cert, member_urn, enable_sense, 
                    credentials, options):
        raise CHAPIv1NotImplementedError('')
