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
from CredentialStore import CSv1Delegate, CSv1Handler, CSv1Guard

# Plugin for logging service implementation

def setup():

    cs_handler = CSv1Handler()
    pm.registerService('csv1handler', cs_handler)

    cs_delegate = CSv1Delegate()
    cs_handler.setDelegate(cs_delegate)

    cs_guard = CSv1Guard() # For speaks-for
    cs_handler.setGuard(cs_guard)

    xmlrpc = pm.getService('xmlrpc')
    xmlrpc.registerXMLRPC('cs1', cs_handler, '/CS')



