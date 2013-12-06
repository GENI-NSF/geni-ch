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

from tools.chapi_log import *
from tools.cert_utils import *
from Exceptions import *
import amsoil.core.pluginmanager as pm
import traceback

# Class to wrap all calls from handlers to delegates
# Holding method context
# 
# Call should :
#  set method
#  grab request cert and pull out email
#  log invocationm
#  adjust client identity
#  create session
#  validate_call (passing session to guard)
#  try:
#     result = delegate.method (passing session to guard)
#     if error:
#       session.rollback
#     else:
#      session.commit
#  except Exception:
#    if exception not of known type (e.g. AUTHZ_ERROR)
#         log stack trace
#    session.rollback
#
# session.close
# log result
# return result

# A CALLER in the Handler should invoke a method by
#
#  with MethodContext(method_name, args_as_dict) as mc:
#     if not mc._error:
#         mc._result = self._delegate.method(arg1, arg2, arg3, mc._session)
#  return mc._result

class MethodContext:
    def __init__(self, authority, log_prefix, 
                 method_name, args_dict, 
                 credentials, options, read_only):
        self._authority = authority
        self._log_prefix = log_prefix
        self._method_name = method_name
        self._args_dict = args_dict
        self._credentials = credentials
        self._options = options
        self._read_only = read_only

        self._client_cert = None
        self._email = None
        try:
            self._client_cert = self._authority.requestCertificate()
            self._email = get_email_from_cert(self._client_cert)
        except Exception as e:
            chapi_info("***MC***", "No request certificate")

        self._error = False

        self._db = pm.getService('chdbengine')
        self._session = self._db.getSession()


    def __enter__(self):
        chapi_log_invocation(self._log_prefix,
                             self._method_name, 
                             self._credentials, 
                             self._options, 
                             self._args_dict, 
                             {'user': self._email})

        if self._authority._guard:
            new_client_cert, new_options = \
                self._authority._guard.adjust_client_identity(self._client_cert, 
                                                              self._credentials, 
                                                              self._options)
            self._client_cert = new_client_cert
            self._options = new_options

            try:
                self._authority._guard.validate_call(self._client_cert, 
                                                     self._method_name,
                                                     self._credentials,
                                                     self._options,
                                                     self._args_dict,
                                                     self._session)
            except Exception as e:
                self._result = self._authority._errorReturn(e)
                self._error = True
        return self

    def __exit__(self, type, value, traceback_object):
#        chapi_info("MC.__exit__", "%s %s %s" % (type, value, traceback_object))
        if type:
            self._result = self._authority._errorReturn(value)
            self._authority._log.error(value)
            if type not in (CHAPIv1ArgumentError, 
                            CHAPIv1DuplicateError, 
                            CHAPIv1AuthorizationError):
                self._authority._log.error(traceback.format_tb(traceback_object))

        if not self._read_only:
            self._session.commit()
        self._session.close()

        chapi_log_result(self._log_prefix, self._method_name,
                         self._result, {'user': self._email})
        return True






