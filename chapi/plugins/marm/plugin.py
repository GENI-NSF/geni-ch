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
from MAv1Implementation import MAv1Implementation
from MAv1Guard import MAv1Guard

# Implementation of MA that works against GPO database. Replace
# Default delegate with MAv1Implementation delegate

def setup():

    config = pm.getService('config')
    config.install("chrm.db_url_filename", "/tmp/chrm_db_url.txt", \
                       "file containing database URL")

    config.install("chrm.authority", "ch-mb.gpolab.bbn.com", \
                       "name of CH/SA/MA authority")

    config.install("flask.debug.client_cert_file", "/home/mbrinn/.gcf/mbrinn-cert.pem", "Debug client cert file")


    delegate = MAv1Implementation()

    guard = MAv1Guard()

    handler = pm.getService('mav1handler')
    handler.setDelegate(delegate)
    handler.setGuard(guard)
