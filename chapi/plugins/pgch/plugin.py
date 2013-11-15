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
from PGCH import PGCHv1Handler, PGCHv1Delegate

# Plugin for PGCH (ProtoGENI CH/SA/MA interface) service

def setup():

   # set up config keys                                                        
   config = pm.getService('config')

   # register xmlrpc endpoint                                                  
   xmlrpc = pm.getService('xmlrpc')

   pgch_handler = PGCHv1Handler()
   pgch_delegate = PGCHv1Delegate()
   pgch_handler.setDelegate(pgch_delegate)

   pgch_handler2 = PGCHv1Handler()
   pgch_delegate2 = PGCHv1Delegate()
   pgch_handler2.setDelegate(pgch_delegate2)

   pm.registerService('pgchv1handler', pgch_handler)

   # name, handler, endpoint                                                   
   xmlrpc.registerXMLRPC('pgch2v1', pgch_handler2, '/PGCH')
   xmlrpc.registerXMLRPC('pgchv1', pgch_handler, '/')
