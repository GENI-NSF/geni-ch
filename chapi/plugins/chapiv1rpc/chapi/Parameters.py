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
import ConfigParser
from tools.chapi_log import *

CONFIG_FILE = '/etc/geni-chapi/chapi.ini'

GENI_CH_DIR = '/usr/share/geni-ch'
CA_DIR = os.path.join(GENI_CH_DIR, 'CA')
MA_DIR = os.path.join(GENI_CH_DIR, 'ma')
SA_DIR = os.path.join(GENI_CH_DIR, 'sa')
GCF_ROOT = os.path.join(GENI_CH_DIR, 'portal', 'gcf.d')

VERSION_NUMBER = '1.0'

NAME_KEY = 'name'
VALUE_KEY = 'val'
DESC_KEY = 'desc'

default_parameters = [
    {
        NAME_KEY: 'chapiv1rpc.ch_cert_root', 
        VALUE_KEY: os.path.join(GCF_ROOT, 'trusted_roots'),
        DESC_KEY: ("Folder which includes trusted clearinghouse certificates"
                   + " for GENI API v3 (in .pem format). If relative path,"
                   + " the root is assumed to be git repo root.")
    },
    {
        NAME_KEY: "chapiv1rpc.ch_cert",
        VALUE_KEY: os.path.join(CA_DIR, 'cacert.pem'),
        DESC_KEY: "Location of CH certificate"
    },
    {
        NAME_KEY: "chapiv1rpc.ch_key",
        VALUE_KEY: os.path.join(CA_DIR, 'cakey.pem'),
        DESC_KEY: "Location of CH private key"
    },
    {
        NAME_KEY: "chapi.ma_cert",
        VALUE_KEY: os.path.join(MA_DIR, 'ma-cert.pem'),
        DESC_KEY: "Location of MA certificate"
    },
    {
        NAME_KEY: "chapi.ma_key",
        VALUE_KEY: os.path.join(MA_DIR, 'ma-key.pem'),
        DESC_KEY: "Location of MA private key"
    },
    {
        NAME_KEY: "chapi.sa_cert",
        VALUE_KEY: os.path.join(SA_DIR, 'sa-cert.pem'),
        DESC_KEY: "Location of SA certificate"
    },
    {
        NAME_KEY: "chapi.sa_key",
        VALUE_KEY: os.path.join(SA_DIR, 'sa-key.pem'),
        DESC_KEY: "Location of SA private key"
    },
    {
        NAME_KEY: "chapi.log_file",
        VALUE_KEY: '/tmp/chapi.log',
        DESC_KEY: "Location of chapi's log file"
    },
    {
        NAME_KEY: "chrm.authority",
        VALUE_KEY: "host.example.com",
        DESC_KEY: "name of CH/SA/MA authority"
    },
    {
        NAME_KEY: "flask.debug.client_cert_file",
        VALUE_KEY: "/path/to/developer/cert.pem",
        DESC_KEY: "Debug client cert file"
    },
    {
        NAME_KEY: 'chrm.db_url',
        VALUE_KEY: 'postgresql://scott:tiger@localhost/chapi',
        DESC_KEY: 'database URL'
    },
    {
        NAME_KEY: "flask.fcgi",
        VALUE_KEY: True,
        DESC_KEY: "Use FCGI server instead of the development server."
    },
    {
        NAME_KEY: "flask.fcgi_port",
        VALUE_KEY: 0,
        DESC_KEY: "Port to bind the Flask RPC to (FCGI server)."
    },
    {
        NAME_KEY: "flask.app_port",
        VALUE_KEY: 8001,
        DESC_KEY: "Port to bind the Flask RPC to (standalone server)."
    },
    {
        NAME_KEY: "flask.debug",
        VALUE_KEY: True,
        DESC_KEY: "Write logging messages for the Flask RPC server."
    }
]


def get_typed_value(parser, section, option, value_type):
    """Get a typed value from a ConfigParser.

    Use the right ConfigParser accessor to get the correct type
    from the ConfigParser. If type is unknown, return None.
    """
    value = None
    if value_type is str:
        value = parser.get(section, option)
    elif value_type is int:
        value = parser.getint(section, option)
    elif value_type is bool:
        value = parser.getboolean(section, option)
    else:
        msg = 'Unknown type %s for default parameter %s'
        chapi_warn('PARAMETERS',
                   msg % (value_type.__name__, pname))
    return value

def param_to_secopt(param):
    """Convert a parameter name to INI section and option.
    Split on the first dot. If not dot exists, return name
    as option, and None for section."""
    sep = '.'
    sep_loc = param.find(sep)
    if sep_loc == -1:
        # no dot in name, skip it
        section = None
        option = param
    else:
        section = param[0:sep_loc]
        option = param[sep_loc+1:]
    return (section, option)

def set_parameters():
    config = pm.getService("config")
    # Set up the defaults
    for param in default_parameters:
        config.install(param[NAME_KEY], param[VALUE_KEY], param[DESC_KEY])
    # Overwrite the defaults with values from the config file
    parser = ConfigParser.SafeConfigParser()
    result = parser.read(CONFIG_FILE)
    if len(result) != 1:
        # file was not read, warn and return
        chapi_warn('PARAMETERS',
                   'Unable to read config file %s' % (CONFIG_FILE))
    else:
        for param in default_parameters:
            pname = param[NAME_KEY]
            (section, option) = param_to_secopt(pname)
            if parser.has_option(section, option):
                value_type = type(param[VALUE_KEY])
                value = get_typed_value(parser, section, option, value_type)
                if value:
                    # If a value was extracted, set it
                    msg = 'Setting parameter %s to %s from %s'
                    chapi_debug('PARAMETERS',
                                msg % (pname, value, CONFIG_FILE))
                    config.set(pname, value)
