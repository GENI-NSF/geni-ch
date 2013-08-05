from chapi.GuardBase import GuardBase

class SAv1InvocationGuard:
    def validate(self, client_cert, credentials, options, args):
        return True

class SAv1RowGuard:
    def permit(self, urn, urn_results):
        return True

class LookupSlicesInvocationGuard(SAv1InvocationGuard): pass
class LookupSliceMembersInvocationGuard(SAv1InvocationGuard): pass
class LookupSlicesRowGuard(SAv1RowGuard): pass

INVOCATION_GUARDS_FOR_METHOD = \
    { 'lookup_slices' : LookupSlicesInvocationGuard(),
      'lookup_slice_members' : LookupSliceMembersInvocationGuard()
      }

ROW_GUARDS_FOR_METHOD = \
    { 'lookup_slices' : LookupSlicesRowGuard()
      }

class SAv1Guard(GuardBase):
    
    def __init__(self):
        super(SAv1Guard, self).__init__()

    def validate_call(self, client_cert, method, credentials, options, args):
        print "SAv1Guard.validate_call : " + method + " " + str(args) + " " + str(options)
        if INVOCATION_GUARDS_FOR_METHOD.has_key(method):
            invocation_guard = INVOCATION_GUARDS_FOR_METHOD[method]
            return invocation_guard.validate(client_cert, credentials, \
                                                 options, args)
        else:
            return True

    def protect_results(self, client_cert, method, results):
        print "SAv1Guard.protect_results : " + method + " " + str(results)
        protected_results = results
        if ROW_GUARDS_FOR_METHOD.has_key(method):
            protected_results = {}
            row_guard = ROW_GUARDS_FOR_METHOD[method]
            for urn in results.keys():
                urn_result = results[urn]
                if row_guard.permit(urn, urn_result):
                    protected_results[urn] = urn_result
        return protected_results
