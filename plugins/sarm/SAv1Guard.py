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

from ABACGuard import *
from ArgumentCheck import *
import tools.SA_constants as SA
from tools.chapi_log import *
from tools.policy_file_checker import PolicyFileChecker

# Specific guard for GPO SA
# Provide a set of invocation checks and row checks per method
class SAv1Guard(ABACGuardBase):

# Methods
#    def create_slice(self, credentials, options):
#    def lookup_slices(self, credentials, options):
#    def update_slice(self, slice_urn, credentials, options):
#    def get_credentials(self, slice_urn, credentials, options):
#    def modify_slice_membership(self, slice_urn,
#    def lookup_slice_members(self, slice_urn, credentials, options):
#    def lookup_slices_for_member(self, member_urn, credentials, options):
#    def register_aggregate(self, slice_urn, aggregate_url, credentials, opts):
#    def remove_aggregate(self, slice_urn, aggregate_url, credentials, opts):
#    def lookup_slice_aggregates(self, slice_urn, credentials, options):
#    def create_project(self, credentials, options):
#    def lookup_projects(self, credentials, options):
#    def update_project(self, project_urn, credentials, options):
#    def modify_project_membership(self, project_urn,
#    def lookup_project_members(self, project_urn, credentials, options):
#    def lookup_projects_for_member(self, member_urn, credentials, options):


    # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {

        # Argument checks for slice methods
        'create_slice' : \
            CreateArgumentCheck(SA.slice_mandatory_fields,\
                                   SA.slice_supplemental_fields),
        'update_slice' : \
            UpdateArgumentCheck(SA.slice_mandatory_fields,\
                                    SA.slice_supplemental_fields,
                                {'slice_urn' : "URN"}),
        'lookup_slices' : \
            LookupArgumentCheck(SA.slice_mandatory_fields,\
                                    SA.slice_supplemental_fields),
        'modify_slice_membership' : SimpleArgumentCheck({'slice_urn' : 'URN'}),
        'lookup_slice_members' : SimpleArgumentCheck({'slice_urn' : 'URN'}),
        'lookup_slices_for_member' : SimpleArgumentCheck({'member_urn' : 'URN'}),
        'get_slice_credentials' : SimpleArgumentCheck({'slice_urn' : 'URN'}),

        # Argument checks for project methods

        'create_project' : \
            CreateArgumentCheck(SA.project_mandatory_fields,\
                                   SA.project_supplemental_fields),
        'update_project' : \
            UpdateArgumentCheck(SA.project_mandatory_fields,
                                SA.project_supplemental_fields,
                                {'project_urn' : "URN"}),
        'lookup_projects' : \
            LookupArgumentCheckMatchOptional(SA.project_mandatory_fields,\
                                    SA.project_supplemental_fields),
        'modify_project_membership' : SimpleArgumentCheck({'project_urn' : 'URN'}),
        'lookup_project_members' : SimpleArgumentCheck({'project_urn' : 'URN'}),
        'lookup_projects_for_member' : SimpleArgumentCheck({'member_urn' : 'URN'}),

        # Argument checks for sliver info aggregate methods
        'create_sliver_info' : CreateArgumentCheck(SA.sliver_info_mandatory_fields,
                                                   SA.sliver_info_supplemental_fields),
        'update_sliver_info' : UpdateArgumentCheck(SA.sliver_info_mandatory_fields,
                                                   SA.sliver_info_supplemental_fields,
                                                   {'sliver_urn' : "URN"}),
        'delete_sliver_info' : SimpleArgumentCheck({'sliver_urn' : 'URN'}),
        'lookup_sliver_info' : LookupArgumentCheckMatchOptional(SA.sliver_info_mandatory_fields,
                                                                SA.sliver_info_supplemental_fields),

        # Argument checks for project request methods
        # No options required (context_type, request_id, resolution_status, resolution_description arguments)
        'create_request' :  None,
        # No options required (context_type, request_id, resolution_status, resolution_description arguments)
        'resolve_pending_request' :  None,
        # No options required (context_type, context_id, status arguments)
        'get_requests_for_context' :  None,
        # No options required (member_id, context_type, context_id, status arguments)
        'get_requests_by_user' :  None,
        # No options required (member_id, context_type, context_id arguments)
        'get_pending_requests_for_user' :  None,
        # No options required (member_id, context_type, context_id arguments)
        'get_number_of_pending_requests_for_user' :  None,
        # No options required (request_id, context_type arguments)
        'get_request_by_id' : None,
        # No options required (role, project_id)
        'invite_member' : None,
        # No options required (invite_id, member_id)
        'accept_invitation' : None

        }


    # Set of invocation checks indexed by method name
    INVOCATION_CHECK_FOR_METHOD = None

    # Name of policies file
    policies_filename = "/etc/geni-chapi/slice_authority_policy.json"

    # Thread to check whether the policies file has changed
    policies_file_checker = None

# argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):
        # Initiate file check thread
        if self.policies_file_checker == None:
            self.policies_file_checker = \
                PolicyFileChecker(self.policies_filename, 5, \
                                      self, SA_LOG_PREFIX)
            self.policies_file_checker.start()

        if self.INVOCATION_CHECK_FOR_METHOD == None:
            policies = \
                parse_method_policies(self.policies_filename)
            self.INVOCATION_CHECK_FOR_METHOD = \
                create_subject_invocation_checks(self, policies)
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None

    # Lookup row check per method (or None if none registered)
    def get_row_check(self, method):
        if self.ROW_CHECK_FOR_METHOD.has_key(method):
            return self.ROW_CHECK_FOR_METHOD[method]
        return None
