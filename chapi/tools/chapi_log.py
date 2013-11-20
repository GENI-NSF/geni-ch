#----------------------------------------------------------------------
# Copyright (c) 2013 Raytheon BBN Technologies
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

# Methods to provide standard logging within CHAPI for 
# invocations, errors, exceptions and other information events

# In this way, the handling of CHAPI messages (what level, to what
# files, what format) can be abstracted away from the rest of the code

import logging
import sys
import traceback

SA_LOG_PREFIX = "SA"
MA_LOG_PREFIX = "MA"
CS_LOG_PREFIX = "CS"
PGCH_LOG_PREFIX = "PGCH"
SR_LOG_PREFIX = "SR"

#chapi_logger = logging.getLogger('chapi')
# FIXME: Get this from the settings in config?
#chapi_logger.setLevel(logging.INFO)
#chapi_fh = logging.FileHandler('/var/log/geni-chapi/chapi.log')
#chapi_formatter = \
#    logging.Formatter('[%(asctime)s]:[%(levelname)-8s]' + \
#                          ':%(name)s:%(message)s')
#chapi_logger.addHandler(chapi_fh)
#chapi_fh.setFormatter(chapi_formatter)
#chapi_audit_logger = logging.getLogger('chapi.audit')

def chapi_get_audit_logger():
    chapi_audit_logger = logging.getLogger('chapi.audit')
    if len(chapi_audit_logger.handlers) == 0:
        chapi_logging_basic_config()
    return chapi_audit_logger

def chapi_get_logger():
    chapi_logger = logging.getLogger('chapi')
    if len(chapi_logger.handlers) == 0:
        chapi_logging_basic_config()
    return chapi_logger

def chapi_logging_basic_config(level=logging.INFO):
    if len(logging.getLogger().handlers) > 0:
        logging.debug("Not redoing basic config")
        return
    fmt = '%(asctime)s %(levelname)-8s %(name)s: %(message)s'
    logging.basicConfig(level=level,format=fmt,datefmt='%m/%d/%Y %H:%M:%S')
    logging.info("Did logging basic config")

# Generic call for logging CHAPI messages at different levels
def chapi_log(prefix, msg, logging_level):
    chapi_logger = chapi_get_logger()
    chapi_logger.log(logging_level, "%s: %s" % (prefix, msg))

# Log a potentially auditable event
def chapi_audit(prefix, msg, lvl=logging.INFO):
    chapi_audit_logger = chapi_get_audit_logger()
    chapi_audit_logger.log(lvl, "%s: %s" % (prefix, msg))

# Log a CHAPI warning message
def chapi_warn(prefix, msg):
    chapi_log(prefix, msg, logging.WARNING)
    chapi_audit(prefix, msg, logging.WARNING)

# Log a CHAPI debug message
def chapi_debug(prefix, msg):
    chapi_log(prefix, msg, logging.DEBUG)

# Log a CHAPI error messagen
def chapi_error(prefix, msg):
    chapi_log(prefix, msg, logging.ERROR)
    chapi_audit(prefix, msg, logging.ERROR)

# Log a CHAPI info message
def chapi_info(prefix, msg):
    chapi_log(prefix, msg, logging.INFO)
    chapi_audit(prefix,("audit:%s" % msg))

# Log a CHAPI criticial message
def chapi_critical(prefix, msg):
    chapi_log(prefix, msg, logging.CRITICAL)
    chapi_audit(prefix, msg, logging.CRITICAL)

# Log a CHAPI exception
def chapi_log_exception(prefix, e):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_info = traceback.format_tb(exc_traceback)
    msg = "Exception: %s\n%s" % (e, "".join(tb_info))
    chapi_error(prefix, msg)
    chapi_audit(prefix, msg, logging.ERROR)

# Log an invocation of a method
def chapi_log_invocation(prefix, method, credentials, options, arguments):
    msg = "Invoked %s Options %s Arguments %s" % (method, options, arguments)
    # FIXME: Info or debug?
    chapi_logger = chapi_get_logger()
    if chapi_logger.isEnabledFor(logging.debug):
        chapi_debug(prefix, msg)
    else:
        if len(msg) > 260:
            chapi_info(prefix, msg[:250] + "...")
        else:
            chapi_info(prefix, msg)

    # FIXME: Send to syslog?
    chapi_audit(prefix, msg, logging.DEBUG)

# Log the result of an invocation of a method
def chapi_log_result(prefix, method, result):
    msg = "Result from %s: %s" % (method, result)
    # FIXME: Info or debug?
    chapi_logger = chapi_get_logger()
    if chapi_logger.isEnabledFor(logging.debug):
        chapi_debug(prefix, msg)
    else:
        if len(msg) > 260:
            chapi_info(prefix, msg[:250] + "...")
        else:
            chapi_info(prefix, msg)

    # FIXME: Send to syslog?
    chapi_audit(prefix, msg, logging.DEBUG)

