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
from SAv1PersistentImplementation import *

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
            CreateArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                   SAv1PersistentImplementation.slice_supplemental_fields),
        'update_slice' : \
            UpdateArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields),
        'lookup_slices' : \
            LookupArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields),
        'modify_slice_membership' : None, # No options required (slice_urn argument)
        'lookup_slice_members' : None, # No options required (slice_urn argument)
        'lookup_slices_for_member' : None, # No options required (member_urn argument)
        'get_credentials' : None, # No options required (slice_urn argument)

        # Argument checks for project methods

        'create_project' : \
            CreateArgumentCheck(SAv1PersistentImplementation.project_mandatory_fields,\
                                   SAv1PersistentImplementation.project_supplemental_fields),
        'update_project' : \
            UpdateArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields),
        'lookup_projects' : \
            LookupArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields),
        'modify_project_membership' : None, # No options required (project_urn argument)
        'lookup_project_members' : None, # No options required (project_urn argument)
        'lookup_projects_for_member' : None, # No options required (member_urn argument)

        # Argument checks for sliver info aggregate methods
        'register_aggregate' : None, # No options required (slice_urn, aggregate_url arguments)
        'remove_aggregate' : None, # No options required (slice_urn, aggregate_url arguments)
        'lookup_slice_aggregates' : None,  # No options required (slice_urn argument)

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
        'get_request_by_id' : None

        }
    

    # Set of invocation checks indexed by method name
    INVOCATION_CHECK_FOR_METHOD = \
        { 

        'create_slice' : \
            SubjectInvocationCheck([
                "ME.MAY_CREATE_SLICE<-ME.IS_OPERATOR",
                "ME.MAY_CREATE_SLICE_$SUBJECT<-ME.IS_LEAD_$SUBJECT", 
                "ME.MAY_CREATE_SLICE_$SUBJECT<-ME.IS_ADMIN_$SUBJECT", 
                "ME.MAY_CREATE_SLICE_$SUBJECT<-ME.IS_MEMBER_$SUBJECT"
                ], assert_slice_role, project_urn_extractor),

        'lookup_slices' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_SLICES<-ME.IS_OPERATOR",
                "ME.MAY_LOOKUP_SLICES_$SUBJECT<-ME.IS_LEAD_$SUBJECT", 
                "ME.MAY_LOOKUP_SLICES_$SUBJECT<-ME.IS_ADMIN_$SUBJECT"
                ], assert_slice_role, standard_subject_extractor),

        'update_slice' : \
            SubjectInvocationCheck([
                "ME.MAY_UPDATE_SLICE<-ME.IS_OPERATOR",
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_LEAD_$SUBJECT", 
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_ADMIN_$SUBJECT"
                ], assert_slice_role, slice_urn_extractor),

        'get_credentials' : \
            SubjectInvocationCheck([
                "ME.MAY_GET_CREDENTIALS<-ME.IS_OPERATOR",
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_LEAD_$SUBJECT", 
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_MEMBER_$SUBJECT",
                "ME.MAY_UPDATE_SLICE_$SUBJECT<-ME.IS_OPERATOR_$SUBJECT"
                ], assert_belongs_to_slice, slice_urn_extractor),

        'modify_slice_membership' : 
            SubjectInvocationCheck([
                "ME.MAY_MODIFY_SLICE_MEMBERSHIP<-ME.IS_OPERATOR",
                "ME.MAY_MODIFY_SLICE_MEMBERSHIP_$SUBJECT<-ME.IS_LEAD_$SUBJECT",
                "ME.MAY_MODIFY_SLICE_MEMBERSHIP_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                ], assert_slice_role, slice_urn_extractor),

        'lookup_slice_members' : 
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_SLICE_MEMBERS<-ME.IS_OPERATOR",
                "ME.MAY_LOOKUP_SLICE_MEMBERS_CREDENTIALS_$SUBJECT<-ME.BELONGS_TO_$SUBJECT"
                ], assert_belongs_to_slice, slice_urn_extractor),

        'lookup_slices_for_member' :
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_SLICES_FOR_MEMBER<-ME.IS_OPERATOR",
                "ME.MAY_LOOKUP_SLICES_FOR_MEMBER_$SUBJECT<-ME.SHARES_SLICE_$SUBJECT"
                ], assert_shares_slice, member_urn_extractor),

        'create_project' : \
            SubjectInvocationCheck([
                "ME.MAY_CREATE_PROJECT<-ME.IS_OPERATOR",
                "ME.MAY_CREATE_PROJECT<-ME.IS_PI"
                ], None, project_urn_extractor),

        'lookup_projects' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_PROJECTS<-CALLER"  # Open to anyone with a legitimate cert
                ], None, standard_subject_extractor),

        'update_project' : \
            SubjectInvocationCheck([
                "ME.MAY_UPDATE_PROJECT<-ME.IS_OPERATOR",
                "ME.MAY_UPDATE_PROJECT_$SUBJECT<-ME.IS_LEAD_$SUBJECT", 
                "ME.MAY_UPDATE_PROJECT_$SUBJECT<-ME.IS_ADMIN_$SUBJECT"
                ], assert_slice_role, project_urn_extractor),

        'modify_project_membership' : \
            SubjectInvocationCheck([
                "ME.MAY_MODIFY_PROJECT_MEMBERSHIP<-ME.IS_OPERATOR",
                "ME.MAY_MODIFY_PROJECT_MEMBERSHIP_$SUBJECT<-ME.IS_LEAD_$SUBJECT",
                "ME.MAY_MODIFY_PROJECT_MEMBERSHIP_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                ], assert_project_role, project_urn_extractor),

        'lookup_project_members' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_PROJECT_MEMBERS_$SUBJECT<-ME.IS_OPERATOR",
                "ME.MAY_LOOKUP_PROJECT_MEMBERS_$SUBJECT<-ME.BELONGS_TO_$SUBJECT"
                ], assert_belongs_to_project, project_urn_extractor),

        'lookup_projects_for_member' : \
            SubjectInvocationCheck([
                "ME.MAY_LOOKUP_PROJECTS_FOR_MEMBER<-ME.IS_OPERATOR",
                "ME.MAY_LOOKUP_PROJECTS_FOR_MEMBER_$SUBJECT<-ME.SHARES_PROJECT_$SUBJECT"
                ], assert_shares_project, member_urn_extractor),

        # *** WRITE ME: Guards for aggregate methods
        'register_aggregate' : None,
        'remove_aggregate' : None,
        'lookup_slice_aggregates' : None,

        # 
        'create_request' :  None, # Open: anyone can request

        # Only if you are operator the lead/admin of the context
        'resolve_pending_request' :  \
            SubjectInvocationCheck([
                "ME.MAY_RESOLVE_PENDING_REQUEST<-ME.IS_OPERATOR",
                "ME.MAY_RESOLVE_PENDING_REQUEST_$SUBJECT<-ME.IS_LEAD_$SUBJECT",
                "ME.MAY_RESOLVE_PENDING_REQUEST_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                ], assert_project_role, request_id_context_extractor),

         # Only if you are operator or the lead/admin of the context
        'get_requests_for_context' :  
            SubjectInvocationCheck([
                "ME.MAY_GET_REQUESTS_FOR_CONTEXT<-ME.IS_OPERATOR",
                "ME.MAY_GET_REQUESTS_FOR_CONTEXT_$SUBJECT<-ME.IS_LEAD_$SUBJECT",
                "ME.MAY_GET_REQUESTS_FOR_CONTEXT_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                ], assert_project_role, request_context_extractor),


         # member_id argument == caller
        'get_requests_by_user' :  \
            SubjectInvocationCheck([
                "ME.MAY_GET_REQUESTS_BY_USER<-ME.IS_OPERATOR",
                "ME.MAY_GET_REQUESTS_BY_USER_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, request_member_extractor),
        'get_pending_requests_for_user' :  \
            SubjectInvocationCheck([
                "ME.MAY_GET_PENDING_REQUESTS_FOR_USER<-ME.IS_OPERATOR",
                "ME.MAY_GET_PENDING_REQUESTS_FOR_USER_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, request_member_extractor),
        'get_number_of_pending_requests_for_user' :  \
            SubjectInvocationCheck([
                "ME.MAY_GET_NUMBER_OF_PENDING_REQUESTS_FOR_USER<-ME.IS_OPERATOR",
                "ME.MAY_GET_NUMBER_OF_PENDING_REQUESTS_FOR_USER_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, request_member_extractor),

        # Only if you are an operator, you are the requestor or the lead/admin of the context  
        'get_request_by_id' : \
            SubjectInvocationCheck([
                "ME.MAY_GET_REQUEST_BY_ID<-ME.IS_OPERATOR",
                "ME.MAY_GET_REQUEST_BY_ID_$SUBJECT<-ME.IS_LEAD_$SUBJECT",
                "ME.MAY_GET_REQUEST_BY_ID_$SUBJECT<-ME.IS_ADMIN_$SUBJECT",
                "ME.MAY_GET_REQUEST_BY_ID<-ME.IS_REQUESTOR"
                ], assert_request_id_requestor_and_project_role, request_id_context_extractor),

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

    # Lookup row check per method (or None if none registered)
    def get_row_check(self, method):
        if self.ROW_CHECK_FOR_METHOD.has_key(method):
            return self.ROW_CHECK_FOR_METHOD[method]
        return None





        
    
