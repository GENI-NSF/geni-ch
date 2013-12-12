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
from tools.guard_utils import *
from tools.geni_constants import *
from Exceptions import *
import amsoil.core.pluginmanager as pm
import os
import sys
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
    def __init__(self, 
                 handler, # Handler object (e.g. SliceAuthority, MemberAuthority)
                 log_prefix, # Prefix (e.g. SA, LOG, MA) to use for logging messages
                 method_name, # Name of invoked method
                 args_dict,  # Dictionary of arguments (beyond credentials and options)
                 credentials, # Credentials argument passed to method call
                 options,  # Options argument passed to method call
                 read_only, # Whether the method is read-only (and thus no need to commit)
                 create_session=True,  # Whether the method requires a DB session 
                 check_existing_urns=True): # Whether to check whether URN arguments exist at call time
        self._handler = handler
        self._log_prefix = log_prefix
        self._method_name = method_name
        self._args_dict = args_dict
        self._credentials = credentials
        self._options = options
        self._read_only = read_only
        self._check_existing_urns = check_existing_urns

        # Grab the request certificate and email at initialization
        self._client_cert = None
        self._email = None
        try:
            self._client_cert = self._handler.requestCertificate()
            self._email = get_email_from_cert(self._client_cert)
        except Exception as e:
            chapi_info("***MC***", "No request certificate")

        self._error = False

        # Create the session if needed
        self._db = pm.getService('chdbengine')
        self._session = None
        if create_session:
            self._session = self._db.getSession()


    # This method is called prior to the 'with MethodContext' block
    def __enter__(self):
        # Log the invocation
        chapi_log_invocation(self._log_prefix,
                             self._method_name, 
                             self._credentials, 
                             self._options, 
                             self._args_dict, 
                             {'user': self._email})

        # If a guard is provided, perform speaks-for identity adjustment
        if self._handler._guard:
            new_client_cert, new_options = \
                self._handler._guard.adjust_client_identity(self._client_cert, 
                                                              self._credentials, 
                                                              self._options)
            self._client_cert = new_client_cert
            self._options = new_options

            try:

                # If we're in maintenance mode, only operators can use CH
                config = pm.getService('config')
                maintenance_outage_location = \
                    config.get('geni.maintenance_outage_location')
                outage_mode = os.path.exists(maintenance_outage_location)
                if outage_mode:
                    if self._session and self._client_cert:
                        user_urn = get_urn_from_cert(self._client_cert)
                        is_operator = \
                            lookup_operator_privilege(user_urn, 
                                                      self._session)
                        if not is_operator:
                            raise CHAPIv1AuthorizationError(
                                "Cannot access GENI Clearinghouse " + 
                                "during maintenance outage")
            

                # Validate the call (arguments and authorization)
                self._handler._guard.validate_call(self._client_cert, 
                                                     self._method_name,
                                                     self._credentials,
                                                     self._options,
                                                     self._args_dict,
                                                     self._check_existing_urns,
                                                     self._session)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self._handleError(e, exc_traceback)
        return self

    # Handle any error in MethodContext processing 
    # Set the error and result fields
    # log traceback for certain errors
    def _handleError(self, e, tb=None):
        if not isinstance(e, CHAPIv1BaseError):
            e = CHAPIv1ServerError(str(e))

        # Log the error, and log teh traceback for certain errors
        self._handler._log.error(e)
        if type(e) in (CHAPIv1ServerError,
                       CHAPIv1NotImplementedError,
                       CHAPIv1DatabaseError):
            if tb:
                self._handler._log.error("\n".join(traceback.format_tb(tb)))

        # Set the error and result
        self._error = True
        self._result = self._handler._errorReturn(e)


    # This is called after the "with MethodContext" block
    # If there was an exception within that block, type is the exception type
    # value is the exception and traceback_object is the stack trace.
    # Otherwise, these are all None
    def __exit__(self, type, value, traceback_object):
#        chapi_info("MC.__exit__", "%s %s %s" % (type, value, traceback_object))
        # If there is an error, handle in standard way (setting result and error)
        if type:
            self._handleError(value, traceback_object)

        # Close the session and commit if necessary
        if self._session:
            if not self._read_only:
                self._session.commit()
            self._session.close()

        # Log the result
        chapi_log_result(self._log_prefix, self._method_name,
                         self._result, {'user': self._email})

        # Returning True means not to propagate the exception. We've handled it here.
        return True







