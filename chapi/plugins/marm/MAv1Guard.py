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

from ABACGuard import *
from ArgumentCheck import *
import MA_constants as MA

# Special class to make sure no one can ask for SSH private keys
# other that for self
class LookupKeysInvocationCheck(SubjectInvocationCheck):
        
    def validate_arguments(self, client_cert, method, options, arguments):
        super(LookupKeysInvocationCheck, self).validate_arguments(
            client_cert, method, options, arguments)
        # If they didn't specify a filter (all by default), 
        # or they explicitly asked for KEY_PRIVATE, there can only
        # be the caller in the list of requested users in 'match'
        if 'filter' not in options or 'KEY_PRIVATE' in options['filter']:
            client_urn = get_urn_from_cert(client_cert)
            for member_urn in self._subjects['MEMBER_URN']:
                if member_urn != client_urn:
                    raise CHAPIv1AuthorizationError(
                        "Can't request private SSH key for user other" + 
                        " than self. Limit match criteria or set filter" + 
                        " explicitly : " + member_urn)


def member_id_extractor(options, arguments):
    member_id = arguments['member_id']
    member_urn = convert_member_uid_to_urn(member_id)
    return {"MEMBER_URN" : member_urn}

# Specific guard for GPO MA
# Provide a set of invocation checks and row checks per method
class MAv1Guard(ABACGuardBase):

# Methods
#   def get_version(self):
#    def lookup_public_member_info(self, credentials, options):
#    def lookup_private_member_info(self, credentials, options):
#    def lookup_identifying_member_info(self, credentials, options):
#    def update_member_info(self, member_urn, credentials, options):
#    def create_key(self, member_urn, credentials, options):
#    def delete_key(self, member_urn, key_id, credentials, options):
#    def update_key(self, member_urn, key_id, credentials, options):
#    def lookup_keys(self, credentials, options):
#    def create_certificate(self, member_urn, credentials, options):


    # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'lookup_public_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                                  MA.public_fields), \
                                    select_fields(MA.optional_fields, \
                                                      MA.public_fields)), 
        'lookup_private_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                                  MA.private_fields), \
                                    select_fields(MA.optional_fields, \
                                                      MA.private_fields)), 
        'lookup_identifying_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                                  MA.identifying_fields), \
                                    select_fields(MA.optional_fields, \
                                                      MA.identifying_fields)), 
        'get_credentials' : SimpleArgumentCheck({'member_urn' : 'URN'}),
        'update_member_info' :  \
            UpdateArgumentCheck({}, {}, {'member_urn' : "URN"}),
        
        'create_key' : \
            CreateArgumentCheck(select_fields(MA.standard_key_fields, \
                                           MA.allowed_create_key_fields), \
                                    select_fields(MA.optional_key_fields, \
                                           MA.allowed_create_key_fields),
                                {'member_urn': 'URN'}), 
        'delete_key' : \
            None,
        'update_key' : \
            UpdateArgumentCheck(select_fields(MA.standard_key_fields, \
                                                  MA.updatable_key_fields), \
                                    select_fields(MA.optional_key_fields, \
                                                      MA.updatable_key_fields),
                                {'member_urn' : 'URN', 'key_id' : 'STRING'}),
        'lookup_key' : \
            LookupArgumentCheck(MA.standard_key_fields, \
                                    MA.optional_key_fields),
        'create_certificate' : \
            None,  
        'create_member' : \
            None, # Check is done in create_member itself

        'list_clients' : None,
        'list_authorized_clients' : None,
        'authorize_client' : None,
        'enable_user': None,
        'add_member_privilege': None,
        'revoke_member_privilege': None,
        }

    # Set of invocation checks indexed by method name
    INVOCATION_CHECK_FOR_METHOD = \
        {
        'lookup_public_member_info' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_PUBLIC_MEMBER_INFO<-ME.IS_OPERATOR"
            ], None, standard_subject_extractor),
        'lookup_identifying_member_info' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_IDENTIFYING_MEMBER_INFO<-ME.IS_AUTHORITY",
                "ME.MAY_LOOKUP_IDENTIFYING_MEMBER_INFO<-ME.IS_OPERATOR", 
                "ME.MAY_LOOKUP_IDENTIFYING_MEMBER_INFO<-ME.IS_LEAD_AND_SEARCHING_EMAIL", 
                "ME.MAY_LOOKUP_IDENTIFYING_MEMBER_INFO_$SUBJECT<-ME.SHARES_PROJECT_$SUBJECT",
                "ME.MAY_LOOKUP_IDENTIFYING_MEMBER_INFO_$SUBJECT<-ME.HAS_PENDING_REQUEST_ON_SHARED_PROJECT_$SUBJECT"
                ], assert_shares_project, standard_subject_extractor),
        'lookup_private_member_info' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_PRIVATE_MEMBER_INFO<-ME.IS_AUTHORITY", 
                "ME.MAY_LOOKUP_PRIVATE_MEMBER_INFO<-ME.IS_OPERATOR", 
                "ME.MAY_LOOKUP_PRIVATE_MEMBER_INFO_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, standard_subject_extractor), 
        'get_credentials' : \
            SubjectInvocationCheck([
                "ME.MAY_GET_CREDENTIALS<-ME.IS_AUTHORITY", 
                "ME.MAY_GET_CREDENTIALS<-ME.IS_OPERATOR",
                "ME.MAY_GET_CREDENTIALS_$SUBJECT<-ME.IS_$SUBJECT" 
                ], None, standard_subject_extractor),
        'update_member_info' : \
            SubjectInvocationCheck([
            "ME.MAY_UPDATE_MEMBER_INFO<-ME.IS_OPERATOR", 
            "ME.MAY_UPDATE_MEMBER_INFO_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, standard_subject_extractor), 
        'create_key' : \
            SubjectInvocationCheck([
                "ME.MAY_CREATE_KEY<-ME.IS_OPERATOR",
                "ME.MAY_CREATE_KEY_$SUBJECT<-ME.IS_$SUBJECT",
                ], None, member_urn_extractor), 
        'delete_key' : \
            SubjectInvocationCheck([
                "ME.MAY_DELETE_KEY<-ME.IS_OPERATOR",
                "ME.MAY_DELETE_KEY_$SUBJECT<-ME.IS_$SUBJECT",
                ], None, member_urn_extractor), 
        'update_key' : \
            SubjectInvocationCheck([
                "ME.MAY_UPDATE_KEY<-ME.IS_OPERATOR",
                "ME.MAY_UPDATE_KEY_$SUBJECT<-ME.IS_$SUBJECT",
                ], None, member_urn_extractor), 
        'lookup_keys' : \
            LookupKeysInvocationCheck([
                "ME.MAY_LOOKUP_KEYS<-ME.IS_AUTHORITY", 
                "ME.MAY_LOOKUP_KEYS<-ME.IS_OPERATOR", 
                "ME.MAY_LOOKUP_KEYS_$SUBJECT<-ME.IS_$SUBJECT",
                "ME.MAY_LOOKUP_KEYS_$SUBJECT<-ME.SHARES_SLICE_$SUBJECT", 
                ], assert_shares_slice, key_subject_extractor), 
        'create_certificate' : 
            SubjectInvocationCheck([
                "ME.MAY_CREATE_CERTIFICATE<-ME.IS_OPERATOR",
                "ME.MAY_CREATE_CERTIFICATE<-ME.IS_AUTHORITY",
                "ME.MAY_CREATE_CERTIFICATE_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, standard_subject_extractor),
        'create_member' : 
            SubjectInvocationCheck([
                "ME.MAY_CREATE_MEMBER<-ME.IS_OPERATOR",
                "ME.MAY_CREATE_MEMBER<-ME.IS_AUTHORITY"
                ], None, None),

        'list_clients' : None,

        'list_authorized_clients' : \
            SubjectInvocationCheck([
                "ME.MAY_LIST_AUTHORIZED_CLIENTS<-ME.IS_AUTHORITY",
                "ME.MAY_LIST_AUTHORIZED_CLIENTS_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, member_id_extractor),
        'authorize_client' : \
            SubjectInvocationCheck([
                "ME.MAY_AUTHORIZE_CLIENT<-ME.IS_AUTHORITY",
                "ME.MAY_AUTHORIZE_CLIENT_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, member_id_extractor),

        # only operator may enable/disable users
        'enable_user' :
            SubjectInvocationCheck([
                    "ME.MAY_ENABLE_USER<-ME.IS_AUTHORITY",
                    "ME.MAY_ENABLE_USER<-ME.IS_OPERATOR", 
                    ], None, None), 
        'add_member_privilege' :
            SubjectInvocationCheck([
                    "ME.MAY_ADD_MEMBER_PRIVILEGE<-ME.IS_AUTHORITY",
                    "ME.MAY_ADD_MEMBER_PRIVILEGE<-ME.IS_OPERATOR", 
                    ], None, None), 
        'revoke_member_privilege' :
            SubjectInvocationCheck([
                    "ME.MAY_REVOKE_MEMBER_PRIVILEGE<-ME.IS_AUTHORITY",
                    "ME.MAY_REVOKE_MEMBER_PRIVILEGE<-ME.IS_OPERATOR", 
                    ], None, None), 
        }


    # Lookup argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None







        
    
