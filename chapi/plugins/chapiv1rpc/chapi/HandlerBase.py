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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
import traceback
from Exceptions import *

xmlrpc = pm.getService('xmlrpc')

# Base class for API handlers, which can have 
#   plug-replaceable delegates and guards
class HandlerBase(xmlrpc.Dispatcher):

    def __init__(self, logger):
        super(HandlerBase, self).__init__(logger)
        self._delegate = None
        self._guard = None

    # Interfaces for setting/getting the delegate (for implementing API calls)
    @serviceinterface
    def setDelegate(self, delegate):
        self._delegate = delegate
    
    @serviceinterface
    def getDelegate(self):
        return self._delegate

    # Interfaces for setting/getting the guard delegate 
    # (for authenticating/authorizing  API calls)
    @serviceinterface
    def setGuard(self, guard):
        self._guard = guard
    
    @serviceinterface
    def getGuard(self):
        return self._guard

    # Standard format for error returns from API calls
    def _errorReturn(self, e):
        """Assembles a GENI compliant return result for faulty methods."""
        return { 'code' : e.code , 'output' : str(e), 'value' : None }
        
    # Standard format for successful returns from API calls
    def _successReturn(self, result):
        """Assembles a GENI compliant return result for successful methods."""
        return { 'code' : 0, 'output' : None, 'value' : result  }

    @serviceinterface
    def requestCertificate(self):
        cert = super(HandlerBase, self).requestCertificate()
        if not cert:
            raise CHAPIv1AuthorizationError('Client certificate required but not provided')
        return cert
