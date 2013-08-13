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
from chapi.Clearinghouse import CHv1Handler, CHv1DelegateBase
from chapi.MemberAuthority import MAv1Handler, MAv1DelegateBase
from chapi.SliceAuthority import SAv1Handler, SAv1DelegateBase
from chapi.GuardBase import GuardBase

def setup():
    # setup config keys
    config = pm.getService("config")

    home = os.getenv('HOME')
    gcf_root = os.path.join(home, '.gcf')
    config.install("chapiv1rpc.ch_cert_root", \
                       os.path.join(gcf_root, 'trusted_roots'), \
                       "Folder which includes trusted clearinghouse certificates for GENI API v3 (in .pem format). If relative path, the root is assumed to be git repo root.")
    config.install("chapiv1rpc.rspec_validation", \
                       True, \
                       "Determines if RSpec shall be validated by the given xs:schemaLocations in the document (may cause downloads of the given schema from the given URL per request).")
    config.install("chapiv1rpc.ch_cert", \
                       os.path.join(gcf_root, "ch-cert.pem"), \
                       "Location of CH certificate")
    config.install("chapiv1rpc.ch_key", \
                       os.path.join(gcf_root, "ch-key.pem"), \
                       "Location of CH private key")
    
    # register xmlrpc endpoint
    xmlrpc = pm.getService('xmlrpc')

    # Invoke the CH, SA and MA and set them with default/dummy 
    # guards and delegates
    # Subsequent plugins should replace these with proper guard and delegate
    # implementations

    ch_handler = CHv1Handler()
    ch_delegate = CHv1DelegateBase()
    ch_guard = GuardBase()
    ch_handler.setDelegate(ch_delegate)
    ch_handler.setGuard(ch_guard)
    pm.registerService('chv1handler', ch_handler)
    xmlrpc.registerXMLRPC('ch1', ch_handler, '/CH') # name, handlerObj, endpoint

    sa_handler = SAv1Handler()
    sa_delegate = SAv1DelegateBase()
    sa_guard = GuardBase()
    sa_handler.setDelegate(sa_delegate)
    sa_handler.setGuard(sa_guard)
    pm.registerService('sav1handler', sa_handler)
    xmlrpc.registerXMLRPC('sa1', sa_handler, '/SA') # name, handlerObj, endpoint

    ma_handler = MAv1Handler()
    ma_delegate = MAv1DelegateBase()
    ma_guard = GuardBase()
    ma_handler.setDelegate(ma_delegate)
    ma_handler.setGuard(ma_guard)
    pm.registerService('mav1handler', ma_handler)
    xmlrpc.registerXMLRPC('ma1', ma_handler, '/MA') # name, handlerObj, endpoint
