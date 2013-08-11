import amsoil.core.pluginmanager as pm
from MAv1Implementation import MAv1Implementation

# Implementation of MA that works against GPO database. Replace
# Default delegate with MAv1Implementation delegate

def setup():

    delegate = MAv1Implementation()
    handler = pm.getService('mav1handler')
    handler.setDelegate(delegate)
