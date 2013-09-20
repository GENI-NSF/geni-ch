#----------------------------------------------------------------------
# Copyright (c) 2011-2013 Raytheon BBN Technologies
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

import amsoil.core.pluginmanager as pm
from ServiceRegistry import SRv1Handler, SRv1Delegate
#from CHv1Implementation import CHv1Implementation
from CHv1PersistentImplementation import CHv1PersistentImplementation
from CHDatabaseEngine import CHDatabaseEngine
from CHv1Guard import CHv1Guard

# This plugin sets the delgate for the CH handler to be the CH Persistent
# Implementation. There are no guards for this handler: all methods
# are public

def setup():

    db_engine = CHDatabaseEngine()
    pm.registerService('chdbengine', db_engine)

#    delegate = CHv1Implementation()

    delegate = CHv1PersistentImplementation()
    guard = CHv1Guard()
    handler = pm.getService('chv1handler')
    handler.setDelegate(delegate)

    sr_handler = SRv1Handler()
    pm.registerService('srv1handler', sr_handler)
    sr_delegate = SRv1Delegate()
    sr_handler.setDelegate(sr_delegate)

    xmlrpc = pm.getService('xmlrpc')
    xmlrpc.registerXMLRPC('sr1', sr_handler, '/SR')


