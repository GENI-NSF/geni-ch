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

import tools.pluginmanager as pm
from gcf.sfa.trust.certificate import Certificate
import os
import traceback
from Exceptions import *

import tools.cert_registry as cert_registry

# Base class for API handlers, which can have 
#   plug-replaceable delegates and guards
class HandlerBase(object):

    def __init__(self, logger):
        self._logger = logger
        self._delegate = None
        self._guard = None
        self._trusted_roots = None
        self._trusted_roots = self.getTrustedRoots()
        config = pm.getService('config')
        self._maintenance_file = config.get('geni.maintenance_outage_location')

    # Get list of trusted roots for handler
    # If not set, initialize from chapiv1rpc.ch_cert_root directory
    def getTrustedRoots(self):
        if self._trusted_roots == None:
            config = pm.getService('config')
            trust_roots = config.get('chapiv1rpc.ch_cert_root')
            pem_files = os.listdir(trust_roots)
            pems = [open(os.path.join(trust_roots, pem_file)).read() \
                        for pem_file in pem_files \
                        if pem_file != 'CATedCACerts.pem']
            self._trusted_roots = [Certificate(string=pem) for pem in pems]
        return self._trusted_roots

    # Interfaces for setting/getting the delegate (for implementing API calls)
    def setDelegate(self, delegate):
        self._delegate = delegate
    
    def getDelegate(self):
        return self._delegate

    # Interfaces for setting/getting the guard delegate 
    # (for authenticating/authorizing  API calls)
    def setGuard(self, guard):
        self._guard = guard
    
    def getGuard(self):
        return self._guard

    # Standard format for successful returns from API calls
    def _successReturn(self, result):
        """Assembles a GENI compliant return result for successful methods."""
        return { 'code' : 0, 'output' : '', 'value' : result  }

    def requestCertificate(self):
        # *** get this from env ***
        cert = cert_registry.lookup_client_cert()
        if not cert:
            raise CHAPIv1AuthorizationError('Client certificate required but not provided')
        return cert

    def _errorReturn(self, e, tb=None):
        """Assembles a GENI compliant return result for faulty methods."""
        if not isinstance(e, CHAPIv1BaseError): # convert common errors into CHAPIv1GeneralError
            e = CHAPIv1ServerError(str(e))
        # do some logging
        self._logger.error(e)
        if type(e) in (CHAPIv1ServerError,
                       CHAPIv1NotImplementedError,
                       CHAPIv1DatabaseError):
            if tb:
                self._logger.error("\n".join(traceback.format_tb(tb)))
            else:
                self._logger.error(traceback.format_exc())
        return {'code' :  e.code , 'value' : None, 'output' : str(e) }
        
    def maintenanceOutage(self):
        return os.path.exists(self._maintenance_file)
