# Base class to perform authentication, authorization and speaks-for validation
class GuardBase(object):

    def __init__(self):
        pass

    # Return whether the given method may be called
    # with given options given the set of provided credentials
    # Optional dictionary of additional call arguments provided (default={})
    def validate(self, client_cert, method, credentials, options, args={}):
        print "VALIDATING " + method + " " + str(options)
        return True


