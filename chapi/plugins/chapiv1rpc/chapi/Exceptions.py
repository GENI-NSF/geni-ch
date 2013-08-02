from amsoil.core.exception import CoreException

class CHAPIv1BaseError(CoreException):
    def __init__(self, code, name, description, comment):
        self.code = code
        self.name = name
        self.description = description
        self.comment = comment

    def __str__(self):
        return "[%s] %s (%s)" % (self.name, self.description, self.comment)

class CHAPIv1AuthenticationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(1, 'AUTHENTICATION', \
                                                 'AUTHENTICATION_ERROR', comment)

class CHAPIv1AuthorizationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(2, 'AUTHORIZATION', \
                                                 'AUTHORIZATION_ERROR', comment)

class CHAPIv1ArgumentError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(3, 'ARGUMENT', 'ARGUMENT_ERROR', \
                                                 comment)

class CHAPIv1DatabseError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(4, 'DATABASE', 'DATABASE_ERROR', \
                                                 comment)

class CHAPIv1NotImplementedError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(5, 'NOT_IMPLEMENTED', \
                                                 'NOT_IMPLEMENTED_ERROR', \
                                                 comment)

class CHAPIv1ServerError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(100, 'SERVER', \
                                                 'SERVER_ERROR', comment)

