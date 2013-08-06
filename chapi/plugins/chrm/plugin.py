import amsoil.core.pluginmanager as pm
from CHv1Implementation import CHv1Implementation
from CHv1PersistentImplementation import CHv1PersistentImplementation
from CHDatabaseEngine import CHDatabaseEngine

def setup():

    # set up config keys
    config = pm.getService('config')
    config.install("chrm.db_url", None, "database URL")

    config.install("chrm.authority", "ch-mb.gpolab.bbn.com", \
                       "name of CH/SA/MA authority")


#    delegate = CHv1Implementation()
    delegate = CHv1PersistentImplementation()
    handler = pm.getService('chv1handler')
    handler.setDelegate(delegate)

    db_engine = CHDatabaseEngine()
    pm.registerService('chdbengine', db_engine)

