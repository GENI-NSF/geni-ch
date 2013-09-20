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
import os.path

GCF_ROOT = "/usr/share/geni-ch/portal/gcf.d"

VERSION_NUMBER = '1.0'

parameters = [
    {
        'name': 'chapiv1rpc.ch_cert_root', 
        'val': os.path.join(GCF_ROOT, 'trusted_roots'),
        'desc': "Folder which includes trusted clearinghouse certificates for GENI API v3 (in .pem format). If relative path, the root is assumed to be git repo root."
    },
    {
        'name': "chapiv1rpc.ch_cert",
        'val': os.path.join(GCF_ROOT, "ch-cert.pem"),
        'desc': "Location of CH certificate"
    },
    {
        'name': "chapiv1rpc.ch_key",
        'val': os.path.join(GCF_ROOT, "ch-key.pem"),
        'desc': "Location of CH private key"
    },
    {
        'name': "chapi.ma_cert",
        'val': '/usr/share/geni-ch/ma/ma-cert.pem',
        'desc': "Location of MA certificate"
    },
    {
        'name': "chapi.ma_key",
        'val': '/usr/share/geni-ch/ma/ma-key.pem',
        'desc': "Location of MA private key"
    },
    {
        'name': "chapi.sa_cert",
        'val': '/usr/share/geni-ch/sa/sa-cert.pem',
        'desc': "Location of SA certificate"
    },
    {
        'name': "chapi.sa_key",
        'val': '/usr/share/geni-ch/sa/sa-key.pem',
        'desc': "Location of SA private key"
    },
    {
        'name': "chrm.authority",
        'val': "ch-mb.gpolab.bbn.com",
        'desc': "name of CH/SA/MA authority"
    },
    {
        'name': "flask.debug.client_cert_file",
        'val': "/home/mbrinn/.gcf/mbrinn-cert.pem",
        'desc': "Debug client cert file"
    },
    {
        'name': 'chrm.db_url',
        'val': 'postgresql://portal:portal@localhost/portal',
        'desc': 'database URL'
    },
    {
        'name': "flask.fcgi",
        'val': True,
        'desc': "Use FCGI server instead of the development server."
    },
    {
        'name': "flask.fcgi_port",
        'val': 0,
        'desc': "Port to bind the Flask RPC to (FCGI server)."
    },
    {
        'name': "flask.app_port",
        'val': 8001,
        'desc': "Port to bind the Flask RPC to (standalone server)."
    },
    {
        'name': "flask.debug",
        'val': True,
        'desc': "Write logging messages for the Flask RPC server."
    }
]


def set_parameters():
    config = pm.getService("config")
    for param in parameters:
        config.install(param['name'], param['val'], param['desc'])
        config.set(param['name'], param['val'])
