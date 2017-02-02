#----------------------------------------------------------------------
# Copyright (c) 2011-2016 Raytheon BBN Technologies
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

# Base class to perform authentication, authorization and speaks-for validation
class GuardBase(object):

    def __init__(self):
        pass

    # Return whether the given method may be called
    # with given options given the set of provided credentials
    # Plus dictionary of additional call arguments provided)
    # and session with which to perform database operations
    def validate_call(self, client_cert, method, credentials, options, args,
                      session):
#        print "VALIDATING " + method + " " + str(options)
        return True

    # Adjust the client identity in case the credentials and options
    # indicate that the caller of the method is not the 'true' caller
    # This method is intended to be overwritten by clients that
    # support 'speaks-for' semantics
    # Returns:
    #   agent_cert - The certificate of the true caller
    #          (which may or may not be the client_cert)
    #   revised_options - Any changes to optiosn to reflect the change in
    #         identity (e.g. placing the original client_cert in as an
    #         option for later accountability)
    def adjust_client_identity(self, client_cert, credentials, options,
                               trusted_roots):
        # Default implementation returns the given client_cert and options
        return client_cert, options



    # Check that the results to the given method are permitted
    # To be returned to caller. If not, modify results accordinlgy
    # per policy (removing entries, masking values, etc.)
    def protect_results(self, client_cert, method, credentials, results):
        return results
