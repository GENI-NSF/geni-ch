import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
import traceback
from Exceptions import *

xmlrpc = pm.getService('xmlrpc')

class HandlerBase(xmlrpc.Dispatcher):

    def __init__(self, logger):
        super(HandlerBase, self).__init__(logger)
        self._delegate = None
        self._guard = None

    @serviceinterface
    def setDelegate(self, delegate):
        self._delegate = delegate
    
    @serviceinterface
    def getDelegate(self):
        return self._delegate

    @serviceinterface
    def setGuard(self, guard):
        self._guard = guard
    
    @serviceinterface
    def getGuard(self):
        return self._guard

    def _errorReturn(self, e):
        """Assembles a GENI compliant return result for faulty methods."""
        if not isinstance(e, CHAPIv1BaseError): # convert common errors into CHAPIv1GeneralError
            e = CHAPIv1ServerError(str(e))

        # do some logging
        self._log.error(e)
        self._log.error(traceback.format_exc())
        return { 'code' : e.code , 'output' : str(e), 'value' : None }
        
    def _successReturn(self, result):
        """Assembles a GENI compliant return result for successful methods."""
        return { 'code' : 0, 'output' : None, 'value' : result  }

