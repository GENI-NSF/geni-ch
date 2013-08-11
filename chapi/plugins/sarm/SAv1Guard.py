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

        
    
