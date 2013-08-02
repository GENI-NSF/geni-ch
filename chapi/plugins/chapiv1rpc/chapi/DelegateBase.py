# Base class for delegate bases that want to authenticate, authorize, 
# Return GENI-style returns

from amsoil.core import serviceinterface
import amsoil.core.pluginmanager as pm
from amsoil.config import expand_amsoil_path
from exceptions import *
import ext.geni

class DelegateBase(object):

    def __init__(self, logger):
        self.logger = logger

    @serviceinterface
    def auth(self, client_cert, credentials, slice_urn=None, privileges=()):
        # check variables
        if not isinstance(privileges, tuple):
            raise TypeError("Privileges need to be a tuple.")
        # collect credentials (only GENI certs, version ignored)
        geni_credentials = []
        for c in credentials:
             if c['geni_type'] == 'geni_sfa':
                 geni_credentials.append(c['geni_value'])

        # get the cert_root
        config = pm.getService("config")
        cert_root = expand_amsoil_path(config.get("chapiv1rpc.ch_cert_root"))
        
        if client_cert == None:
            # work around if the certificate could not be acquired due to the shortcommings of the werkzeug library
            if config.get("flask.debug"):
                import ext.sfa.trust.credential as cred
                client_cert = cred.Credential(string=geni_credentials[0]).gidCaller.save_to_string(save_parents=True)
            else:
                raise CHAPIv1ForbiddenError("Could not determine the client SSL certificate")
        # test the credential
        try:
            cred_verifier = ext.geni.CredentialVerifier(cert_root)
            cred_verifier.verify_from_strings(client_cert, geni_credentials, slice_urn, privileges)
        except Exception as e:
            raise CHAPIv1ForbiddenError(str(e))
        
        user_gid = gid.GID(string=client_cert)
        user_urn = user_gid.get_urn()
        user_uuid = user_gid.get_uuid()
        user_email = user_gid.get_email()
        return user_urn, user_uuid, user_email # TODO document return



    def _errorReturn(self, e):
        """Assembles a GENI compliant return result for faulty methods."""
        if not isinstance(e, CHAPIv1BaseError): # convert common errors into CHAPIv1GeneralError
            e = CHAPIv1ServerError(str(e))
        # do some logging
        self.logger.error(e)
        self.logger.error(traceback.format_exc())
        return { 'geni_api' : 3, 'code' : { 'geni_code' : e.code }, 'output' : str(e) }
        
    def _successReturn(self, result):
        """Assembles a GENI compliant return result for successful methods."""
        return { 'geni_api' : 3, 'code' : { 'geni_code' : 0 }, 'value' : result, 'output' : None }

