import amsoil.core.pluginmanager as pm
from MAv1Implementation import MAv1Implementation

def setup():

    delegate = MAv1Implementation()
    handler = pm.getService('mav1handler')
    handler.setDelegate(delegate)
