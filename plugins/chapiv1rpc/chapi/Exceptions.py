#----------------------------------------------------------------------
# Copyright (c) 2011-2015 Raytheon BBN Technologies
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

from amsoil.core.exception import CoreException

# Module containing a set of standard CH/SA/MA API exceptions

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
AUTHENTICATION_ERROR = 1
AUTHORIZATION_ERROR = 2
ARGUMENT_ERROR = 3
DATABASE_ERROR = 4
DUPLICATE_ERROR = 5
NOT_IMPLEMENTED_ERROR = 100
SERVER_ERROR = 101

# Exception for a failure to authenticate the client credentials at server
class CHAPIv1AuthenticationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(AUTHENTICATION_ERROR, \
                                                 'AUTHENTICATION', \
                                                 'AUTHENTICATION_ERROR', comment)

# Exception for a failure to authorize the given caller for the given call
class CHAPIv1AuthorizationError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(AUTHORIZATION_ERROR, \
                                                 'AUTHORIZATION', \
                                                 'AUTHORIZATION_ERROR', comment)

# Exception for a mistaken (missing, incorrect) set of arguments to an API call
class CHAPIv1ArgumentError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(ARGUMENT_ERROR, \
                                                 'ARGUMENT', 'ARGUMENT_ERROR', \
                                                 comment)

# Exception for a database error (should return the database details)
class CHAPIv1DatabaseError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(DATABASE_ERROR, \
                                                 'DATABASE', 'DATABASE_ERROR', \
                                                 comment)

# Exception for a duplicate entry error (like creating a slice where
# the name is already in use)
class CHAPIv1DuplicateError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(DUPLICATE_ERROR, \
                                             'DUPLICATE', 'DUPLICATE_ERROR', \
                                             comment)

# Exception for invoking a method that is not implemented at given service
class CHAPIv1NotImplementedError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(NOT_IMPLEMENTED_ERROR, \
                                                 'NOT_IMPLEMENTED', \
                                                 'NOT_IMPLEMENTED_ERROR', \
                                                 comment)

# Exception for errors on establishing the client/server connection
class CHAPIv1ServerError(CHAPIv1BaseError):
    def __init__(self, comment):
        super(self.__class__, self).__init__(SERVER_ERROR, \
                                                 'SERVER', \
                                                 'SERVER_ERROR', comment)

