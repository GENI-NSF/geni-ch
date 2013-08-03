from amsoil.core.exception import CoreException

class CHAPIv1BaseError(CoreException):
    def __init__(self, code, name, description, comment):
        self.code = code
        self.name = name
        self.description = description
        self.comment = comment

    def __str__(self):
        return "[%s] %s (%s)" % (self.name, self.description, self.comment)

# Standard error codes
NO_ERROR = 0
AUTENTICATION_ERROR = 1
AUTHORIZATION_ERROR = 2
ARGUMENT_ERROR = 3
DATABASE_ERROR = 4
NOT_IMPLEMENTED_ERROR = 100
SERVER_ERROR = 101

class CHAPIv1AuthenticationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(AUTHENTICATION_ERROR, \
                                                 'AUTHENTICATION', \
                                                 'AUTHENTICATION_ERROR', comment)

class CHAPIv1AuthorizationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(AUTHORIZATION_ERROR, \
                                                 'AUTHORIZATION', \
                                                 'AUTHORIZATION_ERROR', comment)

class CHAPIv1ArgumentError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(ARGUMENT_ERROR, \
                                                 'ARGUMENT', 'ARGUMENT_ERROR', \
                                                 comment)

class CHAPIv1DatabseError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(DATABASE_ERROR, \
                                                 'DATABASE', 'DATABASE_ERROR', \
                                                 comment)

class CHAPIv1NotImplementedError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(NOT_IMPLEMENTED_ERROR, \
                                                 'NOT_IMPLEMENTED', \
                                                 'NOT_IMPLEMENTED_ERROR', \
                                                 comment)

class CHAPIv1ServerError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(SERVER_ERROR, \
                                                 'SERVER', \
                                                 'SERVER_ERROR', comment)

