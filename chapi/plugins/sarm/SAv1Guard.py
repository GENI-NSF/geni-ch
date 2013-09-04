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
    # *** FINISH
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'create_slice' : \
            CreateArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                   SAv1PersistentImplementation.slice_supplemental_fields),
        'update_slice' : \
            UpdateArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields),
        'lookup_slices' : \
            LookupArgumentCheck(SAv1PersistentImplementation.slice_mandatory_fields,\
                                    SAv1PersistentImplementation.slice_supplemental_fields)
        }
    

    # Set of invocation checks indexed by method name
    # *** FINISH
    INVOCATION_CHECK_FOR_METHOD = \
        { 
        # lookup_slice_members can be called by anyone who is either
        #   - a member of the project to which the slice belongs
        #   - an operator
        'lookup_slice_members' : 
        ABACInvocationCheck(asserters= [
                OperatorAsserter(), 
                ProjectMemberAsserterByCert()
                ],
                            queries = [["C", "is_operator"], QueryProjectMemberBySliceURN()])
    }

    # Set of row checks indexed by method name
    # *** FINISH
    ROW_CHECK_FOR_METHOD = \
        { 
        # Rows returned from lookup_slices must belong to a project that the caller belongs to
        # Unless the requester is an operator, in which case all rows are okay to return
        'lookup_slices' : 
        ABACRowCheck(asserters = [
                OperatorAsserter(), 
                ProjectMemberAsserterByCert()
                ],
                     queries = [["C", "is_operator"], QueryProjectMemberBySliceURN()]) 
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





        
    
