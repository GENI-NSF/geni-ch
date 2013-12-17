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
import os, os.path

from Portal import Portalv1Handler, Portalv1Delegate, Portalv1Guard

# Plugin for GPO Portal tailored query service

def setup():

   # set up config keys                                                        
   config = pm.getService('config')

   # register xmlrpc endpoint                                                  
   xmlrpc = pm.getService('xmlrpc')

   portal_handler = Portalv1Handler()
   portal_delegate = Portalv1Delegate()
   portal_handler.setDelegate(portal_delegate)
   portal_guard = Portalv1Guard()
   portal_handler.setGuard(portal_guard)

   pm.registerService('portalv1handler', portal_handler)

   # name, handler, endpoint                                                   
   xmlrpc.registerXMLRPC('portal', portal_handler, '/PORTAL')
