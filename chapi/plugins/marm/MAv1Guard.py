#----------------------------------------------------------------------
# Copyright (c) 2011-2014 Raytheon BBN Technologies
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
import tools.MA_constants as MA

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
                                              MA.public_fields), \
                                select_fields(MA.standard_plus_optional, \
                                              MA.match_fields)), 
        'lookup_private_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                              MA.private_fields), \
                                select_fields(MA.optional_fields, \
                                              MA.private_fields), \
                                select_fields(MA.standard_plus_optional, \
                                              MA.match_fields)), 
        'lookup_identifying_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                              MA.identifying_fields), \
                                select_fields(MA.optional_fields, \
                                              MA.identifying_fields), \
                                select_fields(MA.standard_plus_optional, \
                                              MA.match_fields)), 
        'lookup_public_identifying_member_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                              MA.public_fields+MA.identifying_fields), \
                                select_fields(MA.optional_fields, \
                                              MA.public_fields+MA.identifying_fields), \
                                select_fields(MA.standard_plus_optional, \
                                              MA.match_fields)), 
        'lookup_login_info' : \
            LookupArgumentCheck(select_fields(MA.standard_fields, \
                                                  MA.public_fields+MA.identifying_fields+MA.private_fields),
                                select_fields(MA.optional_fields, 
                                                  MA.public_fields+MA.identifying_fields+MA.private_fields),
                                ['_GENI_MEMBER_EPPN']),
        'get_credentials' : SimpleArgumentCheck({'member_urn' : 'URN'}),
        'update_member_info' :  \
            UpdateArgumentCheck({}, {}, {'member_urn' : "URN"}),
        
        'create_key' : \
            CreateArgumentCheck(select_fields(MA.standard_key_fields, \
                                           MA.allowed_create_key_fields), \
                                    select_fields(MA.optional_key_fields, \
                                           MA.allowed_create_key_fields)), 
        'delete_key' : \
            None,
        'update_key' : \
            UpdateArgumentCheck(select_fields(MA.standard_key_fields, \
                                                  MA.updatable_key_fields), \
                                    select_fields(MA.optional_key_fields, \
                                                      MA.updatable_key_fields),
                                {'key_id' : 'STRING'}),
        'lookup_keys' : \
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
        'add_member_attribute': SimpleArgumentCheck({'member_urn' : 'URN',
                                                     'name' : 'STRING',
                                                     'value' : 'STRING',
                                                     'self_asserted' : 'STRING'}),
        'remove_member_attribute': SimpleArgumentCheck({'member_urn' : 'URN',
                                                        'name' : 'STRING',
                                                        'value' : 'STRING'
                                                        }),
        }

    # Set of invocation checks indexed by method name
    INVOCATION_CHECK_FOR_METHOD = None

    # Lookup argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):
        if self.INVOCATION_CHECK_FOR_METHOD == None:
            policies = \
                parse_method_policies("/etc/geni-chapi/member_authority_policy.json")
            self.INVOCATION_CHECK_FOR_METHOD = \
                create_subject_invocation_checks(policies)
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None







        
    
