#----------------------------------------------------------------------
# Copyright (c) 2011-2014 Raytheon BBN Technologies
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
from chapi.Clearinghouse import CHv1Handler, CHv1DelegateBase
from chapi.MemberAuthority import MAv1Handler, MAv1DelegateBase
from chapi.SliceAuthority import SAv1Handler, SAv1DelegateBase
from chapi.GuardBase import GuardBase
from chapi.Parameters import set_parameters, configure_logging

def setup():
    # load all the parameter values into the config database
    set_parameters()

    # Configure logging
    configure_logging()

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
