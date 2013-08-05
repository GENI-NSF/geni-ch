from chapi.GuardBase import GuardBase

class SAv1Guard(GuardBase):
    
    def __init__(self):
        super(SAv1Guard, self).__init__()

    def validate_call(self, client_cert, method, credentials, options, args):
        print "SAv1Guard.validate_call : " + method + " " + str(args) + " " + str(options)
        return True

    def protect_results(self, client_cert, method, results):
        print "SAv1Guard.protect_results : " + method + " " + str(results)
        return results
