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

# Specific guard for GPO SA
# Provide a set of invocation checks and row checks per method
class SAv1Guard(ABACGuardBase):

    INVOCATION_CHECKS_FOR_METHOD = \
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

    ROW_CHECKS_FOR_METHOD = \
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

    def get_invocation_check(self, method):
        if self.INVOCATION_CHECKS_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECKS_FOR_METHOD[method]
        return None

    def get_row_check(self, method):
        if self.ROW_CHECKS_FOR_METHOD.has_key(method):
            return self.ROW_CHECKS_FOR_METHOD[method]
        return None




        
    
