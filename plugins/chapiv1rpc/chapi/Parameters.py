# ----------------------------------------------------------------------
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
# ----------------------------------------------------------------------

import tools.pluginmanager as pm

from tools.chapi_log import *
from Exceptions import *

import ConfigParser
import logging
import logging.config
import logging.handlers
import os
import os.path

GENI_CH_CONF_DIR = '/etc/geni-chapi'
CONFIG_FILE = os.path.join(GENI_CH_CONF_DIR, 'chapi.ini')
DEV_CONFIG_FILE = os.path.join(GENI_CH_CONF_DIR, 'chapi-dev.ini')
AUX_CONFIG_FILE = None

GENI_CH_DIR = '/usr/share/geni-ch'
CA_DIR = os.path.join(GENI_CH_DIR, 'CA')
MA_DIR = os.path.join(GENI_CH_DIR, 'ma')
SA_DIR = os.path.join(GENI_CH_DIR, 'sa')
GCF_ROOT = os.path.join(GENI_CH_DIR, 'portal', 'gcf.d')

VERSION_NUMBER = '2'

# NOTE: Some parameters have default values and are thus optional in chapi.ini
# Values in chapi.in override the defaults if they are there.
# But some parameters do not have defaults, and if chapi.ini does not
# provide them, an error message is logged and the process throws an exception.
# If chapi.ini has a parameter no listed in default_parameters,
# an message is logged but no exception is thrown.

NAME_KEY = 'name'
VALUE_KEY = 'val'
DESC_KEY = 'desc'

default_parameters = [
    {
        NAME_KEY: 'chapiv1rpc.ch_cert_root',
        VALUE_KEY: os.path.join(GCF_ROOT, 'trusted_roots'),
        DESC_KEY: ("Folder which includes trusted clearinghouse certificates" +
                   " for GENI API v3 (in .pem format). If relative path," +
                   " the root is assumed to be git repo root.")
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
        VALUE_KEY: '/var/log/geni-chapi/chapi.log',
        DESC_KEY: "Location of CHAPI's log file"
    },
    {
        NAME_KEY: "chapi.log_config_file",
        VALUE_KEY: '/etc/geni-chapi/logging_config.conf',
        DESC_KEY: "Location of CHAPI's logging configuration file"
    },
    {
        NAME_KEY: "chapi.ssl_config_file",
        VALUE_KEY: os.path.join(CA_DIR, 'openssl.cnf'),
        DESC_KEY: "Location of CHAPI's SSL configuration file"
    },
    {
        NAME_KEY: "chapi.log_verbose",
        VALUE_KEY: False,
        DESC_KEY: "Set true to enable verbose debug logging in CHAPI."
    },
    {
        NAME_KEY: "chapi.log_level",
        VALUE_KEY: "INFO",
        DESC_KEY: "CHAPI logging level."
    },
    {
        NAME_KEY: "chapi.portal_admin_email",
        # No VALUE_KEY default
        DESC_KEY: "portal admin email."
    },
    {
        NAME_KEY: "chapi.portal_help_email",
        # No VALUE_KEY default
        DESC_KEY: "portal help email."
    },
    {
        NAME_KEY: "chapi.ch_from_email",
        # No VALUE_KEY default
        DESC_KEY: "chapi from email"
    },
    {
        NAME_KEY: "chrm.authority",
        # No VALUE_KEY default
        DESC_KEY: "Name of CH/SA/MA authority"
    },
    {
        NAME_KEY: 'chrm.db_url',
        # No VALUE_KEY default
        DESC_KEY: 'Database URL'
    },
    {
        NAME_KEY: "geni.maintenance_outage_location",
        VALUE_KEY: "/etc/geni-ch/geni_maintenance_outage.msg",
        DESC_KEY: "Location of the GENI 'maintenance outage' message"
    }
]


# Allow clients to set an optional auxiliary config file to
# be parsed after CONFIG_FILE and DEV_CONFIG_FILE
def set_auxiliary_config_file(filename):
    global AUX_CONFIG_FILE
    AUX_CONFIG_FILE = os.path.join(GENI_CH_CONF_DIR, filename)


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

    required_config_params = []
    default_parameter_names = []  # Keep list of all defined parameter names
    for param in default_parameters:
        default_parameter_names.append(param[NAME_KEY])

    # Set up the defaults. Keep track of params with no defaults
    # Which must be provided by chapi.ini
    for param in default_parameters:
        if VALUE_KEY in param:
            config.install(param[NAME_KEY], param[VALUE_KEY], param[DESC_KEY])
        else:
            required_config_params.append(param[NAME_KEY])

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
            value = None
            value_type = str
            source = "default_parameters"
            if VALUE_KEY in param:
                value = param[VALUE_KEY]
                value_type = type(value)
            if parser.has_option(section, option):
                value = get_typed_value(parser, section, option, value_type)
                source = CONFIG_FILE
            if value is not None:
                # If a value was extracted, set it
                msg = 'Setting parameter %s to %s from %s'
                chapi_info('PARAMETERS',
                           msg % (pname, value, source))
                config.set(pname, value)
                if pname in required_config_params:
                    required_config_params.remove(pname)

    # If any required parameters are not provided by chapi.ini, log
    # error and raise exception
    if len(required_config_params) > 0:
        for pname in required_config_params:
            chapi_info('PARAMETERS',
                       'Required parameter not set in %s: %s' %
                       (CONFIG_FILE, pname))

        raise CHAPIv1ConfigurationError("Required params missing %s: %s" %
                                        (CONFIG_FILE,
                                         ",".join(required_config_params)))

    # If any parameters are provided in chapi.ini but not in default_parameters
    # Warn but don't raise exception
    for section in parser.sections():
        for item in parser.items(section):
            pname = "%s.%s" % (section, item[0])
            if pname not in default_parameter_names:
                chapi_info('PARAMETERS',
                           'Unrecognized parameter found in %s: %s' %
                           (CONFIG_FILE, pname))

    # Overwrite the base settings with values from the developer config file
    override_parameters(DEV_CONFIG_FILE, "developer")

    # If an 'auxiliary' config file is provided,
    # override the parameters from that file
    if AUX_CONFIG_FILE:
        override_parameters(AUX_CONFIG_FILE, "auxiliary")


def override_parameters(config_filename, config_label):

    config = pm.getService("config")

    parser = ConfigParser.SafeConfigParser()
    result = parser.read(config_filename)
    if len(result) != 1:
        # file was not read, warn and return
        chapi_debug('PARAMETERS',
                    'Unable to read developer %s file %s' %
                    (config_label, config_filename))
    else:
        chapi_warn('PARAMETERS',
                   "Over-riding configs using %s config file %s" %
                   (config_label, config_filename))
        # FIXME: Only allow log settings to be changed?
        for param in default_parameters:
            pname = param[NAME_KEY]
            (section, option) = param_to_secopt(pname)
            if parser.has_option(section, option):
                if VALUE_KEY in param:
                    value_type = type(param[VALUE_KEY])
                else:
                    value_type = str
                value = get_typed_value(parser, section, option, value_type)
                if value is not None:
                    # If a value was extracted, set it
                    msg = 'Setting parameter %s to %s from %s'
                    chapi_info('PARAMETERS',
                               msg % (pname, value, config_filename))
                    config.set(pname, value)


def configure_logging():
    config = pm.getService("config")

    # If we got the verbose setting certain long log messages will be logged
    chapi_do_debug = config.get("chapi.log_verbose")
    if chapi_do_debug:
        chapi_info("LOGGING", "Will log verbosely")
        verboseObj.setVerbose()

    # Set the log level
    level = logging.INFO
    optlevel = 'INFO'
    config_log_level_string = config.get("chapi.log_level")
    if config_log_level_string.strip().upper() == "DEBUG":
        optlevel = 'DEBUG'
        level = logging.DEBUG
    elif config_log_level_string.strip().upper() == "INFO":
        optlevel = 'INFO'
        level = logging.INFO
    elif config_log_level_string.strip().upper() == "WARN":
        optlevel = 'WARNING'
        level = logging.WARNING
    elif config_log_level_string.strip().upper() == "WARNING":
        optlevel = 'WARNING'
        level = logging.WARNING
    elif config_log_level_string.strip().upper() == "ERROR":
        optlevel = 'ERROR'
        level = logging.ERROR
    elif config_log_level_string.strip().upper() == "CRITICAL":
        optlevel = 'CRITICAL'
        level = logging.CRITICAL
    else:
        chapi_warn("LOGGING", "Unknown log level %s ignored" % config_log_level_string)
    chapi_info("LOGGING", "CHAPI log level is %s" % optlevel)

    deft = {}
    deft['loglevel'] = optlevel
    deft['logfilename'] = config.get("chapi.log_file")

    # Create any needed directories for chapi.log_file
    # FIXME: Creating isn't enough - we need the dir to be owned by www-data:www-data
    if not os.path.exists(os.path.dirname(deft['logfilename'])):
        chapi_error("LOGGING", "Dir for log file not there: %s" % deft['logfilename'])
        try:
            os.makedirs(os.path.dirname(deft['logfilename']))
        except EnvironmentError, e:
            chapi_error("LOGGING", "Failed to create log file path %s: %s" % (deft['logfilename'], e))

    # Get the log config file
    logConfigFilename = config.get("chapi.log_config_file")
    # look for it as is or after os.path.abspath()
    fns = [logConfigFilename, os.path.abspath(logConfigFilename)]
    found = False
    for fn in fns:
        if os.path.exists(fn) and os.path.getsize(fn) > 0:
            # Only new loggers get the parameters in the config file.
            # If disable_existing is True(default), then existing loggers are disabled,
            # unless they (or ancestors, not 'root') are explicitly listed in the config file.
            try:
                logging.info("About to configure logging from file %s", fn)
                logging.config.fileConfig(fn, defaults=deft, disable_existing_loggers=False)
                logging.info("Configured logging from file %s", fn)
                found = True
            except Exception, e:
                import traceback
                logging.error("Failed to configure logging from %s: %s", fn, e)
                logging.debug(traceback.format_exc())
            break

    if not found:
        chapi_logging_basic_config(level)
        logging.warn("Failed to find or use CHAPI log config file %s", logConfigFilename)

    # Clean up the old loggers so they stop sending output to the old places
    amsoillogger = logging.getLogger("amsoil")
    if amsoillogger.getEffectiveLevel() != level:
        logging.debug("AMSoil logger: resetting effective log level")
        amsoillogger.setLevel(level)
    toremove = None
    handlers = amsoillogger.handlers
    if len(handlers) == 0:
        # logging.debug("0 handlers for amsoil logger")
        if amsoillogger.parent:
            handlers = amsoillogger.parent.handlers
            logging.debug("Looking at parent for the proper handlers (has %d)", len(handlers))
    for handler in handlers:
        # remove the old handler that put this in amsoil.log
        if isinstance(handler, logging.FileHandler):
            logging.debug("amsoil handler filename: %s, logfilename: %s", handler.baseFilename, deft['logfilename'])
            if not handler.baseFilename.startswith(deft['logfilename']):
                logging.info("Removing handler from amsoil logger with filename %s" % handler.baseFilename)
                toremove = handler
                # Online example says instead to do:
                #            handler.filter=lambda x: False
                break
            else:
                fn = handler.baseFilename
                logging.debug("Keeping amsoil handler with level %s, formatter %s, file %s", logging.getLevelName(handler.level), handler.formatter._fmt, fn)
        else:
            logging.debug("Keeping amsoil handler (non file) with level %s, formatter %s", logging.getLevelName(handler.level), handler.formatter._fmt)

    if toremove:
        amsoillogger.removeHandler(toremove)
#    else:
#        logging.debug("Failed to find any old amsoil handler to remove")

    chapilogger = logging.getLogger("chapi")
    toremove = None
    handlers = chapilogger.handlers
    if len(handlers) == 0:
        # logging.debug("0 handlers for chapi logger")
        if chapilogger.parent:
            handlers = chapilogger.parent.handlers
            logging.debug("Looking at parent for the proper handlers (has %d)", len(handlers))
    for handler in handlers:
        # remove the old handler that put this in amsoil.log
        if isinstance(handler, logging.FileHandler):
            logging.debug("chapi handler filename: %s, logfilename: %s", handler.baseFilename, deft['logfilename'])
            if not handler.baseFilename.startswith(deft['logfilename']):
                logging.info("Removing handler from chapi logger with filename %s, level %s, formatter %s" % (handler.baseFilename, logging.getLevelName(handler.level), handler.formatter._fmt))
                toremove = handler
                # Online example says instead to do:
                #            handler.filter=lambda x: False
                break
            else:
                fn = handler.baseFilename
                logging.debug("Keeping chapi handler with level %s, formatter %s, file %s", logging.getLevelName(handler.level), handler.formatter._fmt, fn)
        else:
            logging.debug("Keeping chapi handler (non file) with level %s, formatter %s", logging.getLevelName(handler.level), handler.formatter._fmt)
    if toremove:
        chapilogger.removeHandler(toremove)
#    else:
#        logging.debug("Failed to find any old chapi handler")

    chapi_info("LOGGING", "Done configuring CHAPI logging")
