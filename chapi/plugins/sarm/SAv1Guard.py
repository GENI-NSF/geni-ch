from ABACGuard import *

class SAv1Guard(ABACGuardBase):

    INVOCATION_CHECKS_FOR_METHOD = \
        { 
        'lookup_slice_members' : 
        ABACInvocationCheck(asserters= [
                OperatorAsserter(), 
                ProjectMemberAsserterByCert()
                ],
                            queries = [["C", "is_operator"], QueryProjectMemberBySliceURN()])
    }

    ROW_CHECKS_FOR_METHOD = \
        { 
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

        
    
