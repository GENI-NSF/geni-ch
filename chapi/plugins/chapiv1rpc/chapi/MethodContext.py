#----------------------------------------------------------------------
# Copyright (c) 2011-2014 Raytheon BBN Technologies
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
                 session=None, # Optionally provide an existing session in which to perform method
                 cert_required=True, # Whether the client_cert is required
                 create_session=True):  # Whether the method requires a DB session 
        self._handler = handler
        self._log_prefix = log_prefix
        self._method_name = method_name
        self._args_dict = args_dict
        self._credentials = credentials
        self._options = options
        self._read_only = read_only
        self._provided_session = (session != None)
        self._cert_required = cert_required

        # Grab the request certificate and email at initialization
        self._client_cert = None
        self._email = None
        if self._cert_required:
            self._client_cert = self._handler.requestCertificate()
            if not self._client_cert:
                raise CHAPIv1ArgumentError("No request certificate")

        if self._client_cert:
            try:
                self._email = get_email_from_cert(self._client_cert)
            except Exception as e:
                chapi_info("MethodContext", "Error extracting email from cert");

        self._error = False

        # Create the session if needed
        self._db = pm.getService('chdbengine')
        self._session = session
        if create_session and not session:
            self._session = self._db.getSession()


    # This method is called prior to the 'with MethodContext' block
    def __enter__(self):
        # If a guard is provided, perform speaks-for identity adjustment
        if self._handler._guard:
            new_client_cert, new_options = \
                self._handler._guard.adjust_client_identity(self._client_cert, 
                                                              self._credentials, 
                                                              self._options)
            if (self._client_cert != new_client_cert):
                self._client_cert = new_client_cert
                self._options = new_options
                # Extract the email from the client cert because it may
                # have changed (been adjusted)
                if self._client_cert:
                    try:
                        self._email = get_email_from_cert(self._client_cert)
                    except Exception as e:
                        msg = "Error extracting email from new client cert"
                        chapi_info("MethodContext", msg)

            # Log the invocation with the adjusted email
            chapi_log_invocation(self._log_prefix,
                                 self._method_name,
                                 self._credentials,
                                 self._options,
                                 self._args_dict,
                                 {'user': self._email})

            try:

                # If we're in maintenance mode, only operators and authorities can use CH
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
                        is_authority = lookup_authority_privilege(user_urn, self._session)
#                        chapi_info("OUTAGE", "USER_URN = %s IS_OPERATOR = %s IS_AUTHORITY = %s" % 
#                                   (user_urn, is_operator, is_authority))
                        if not is_operator and not is_authority:
                            raise CHAPIv1AuthorizationError(
                                "Cannot access GENI Clearinghouse " + 
                                "during maintenance outage")
            

                # Validate the call (arguments and authorization)
                self._handler._guard.validate_call(self._client_cert, 
                                                     self._method_name,
                                                     self._credentials,
                                                     self._options,
                                                     self._args_dict,
                                                     self._session)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self._handleError(e, exc_traceback)
        else:
            # No guard, just log the invocation
            chapi_log_invocation(self._log_prefix,
                                 self._method_name,
                                 self._credentials,
                                 self._options,
                                 self._args_dict,
                                 {'user': self._email})
        return self

    # Handle any error in MethodContext processing 
    # Set the error and result fields
    # log traceback for certain errors
    def _handleError(self, e, tb=None):
        if not isinstance(e, CHAPIv1BaseError):
            e = CHAPIv1ServerError(str(e))

        # Log the error, and log the traceback for certain errors
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
#        chapi_info("MethodContext", "__exit__ %s %s %s" % (type, value, traceback_object))
        # If there is an error, handle in standard way (setting result and error)
        if type:
            self._handleError(value, traceback_object)

        # Close the session and commit if necessary
        if self._session and not self._provided_session:
            try:
                if not self._read_only:
                    if self._error:
                        self._session.rollback()
                    else:
                        self._session.commit()
                self._session.close()
            except Exception as db_error:
                # We got an error committing, rolling back or closing session
                # If there's an existing error
                # Log the database error, but return the previous  error
                # Otherwise return the database error
                exc_type, exc_value, exc_traceback = sys.exc_info()
                if self._error:
                    pretty_db_error_traceback = \
                        "\n".join(traceback.format_tb(exc_traceback))
                    self._handler._log.error(pretty_db_error_traceback)
                else:
                    self._handleError(db_error, exc_traceback)
                

        # Log the result
        chapi_log_result(self._log_prefix, self._method_name,
                         self._result, {'user': self._email})

        # Returning True means not to propagate the exception. We've handled it here.
        return True







