import amsoil.core.pluginmanager as pm
from SAv1PersistentImplementation import SAv1PersistentImplementation
from SAv1Guard import SAv1Guard

def setup():

    # set up config keys
    config = pm.getService('config')
    config.install("chrm.db_url_filename", "/tmp/chrm_db_url.txt", \
                       "file containing database URL")

    config.install("chrm.authority", "ch-mb.gpolab.bbn.com", \
                       "name of CH/SA/MA authority")

    delegate = SAv1PersistentImplementation()
    guard = SAv1Guard()
    handler = pm.getService('sav1handler')
    handler.setDelegate(delegate)
    handler.setGuard(guard)

