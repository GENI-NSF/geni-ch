
import amsoil.core.pluginmanager as pm
from OpsMon import OpsMonHandler

# Load the handler for the appropriate paths
# Note this line must be present in the apache config for ch_ssl:
#  ScriptAliasMatch /info/*/* /usr/share/geni-ch/chapi/AMsoil/src/main.py

def setup():
    rest = pm.getService("rest")
    opsmon_handler = OpsMonHandler()
    pm.registerService('opsmon_handler', opsmon_handler)
    rest.registerREST('opsmon',  OpsMonHandler.handle_opsmon_request, 
                      '/info/<variety>/<id>',
                      methods=["GET"],
                      defaults={})




