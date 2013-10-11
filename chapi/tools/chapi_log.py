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

chapi_logger = logging.getLogger('chapi')
chapi_logger.setLevel(logging.DEBUG)
chapi_fh = logging.FileHandler('/tmp/chapi.log')
chapi_formatter = \
    logging.Formatter('[%(asctime)s] [%(levelname)s]' + \
                          ' %(message)s')
chapi_logger.addHandler(chapi_fh)
chapi_fh.setFormatter(chapi_formatter)


# Generic call for logging CHAPI messages at different levels
def chapi_log(prefix, msg, logging_level):
    chapi_logger.log(logging_level, "%s: %s" % (prefix, msg))

# Log a CHAPI warning message
def chapi_warn(prefix, msg):
    chapi_log(prefix, msg, logging.WARNING)

# Log a CHAPI debug message
def chapi_debug(prefix, msg):
    chapi_log(prefix, msg, logging.DEBUG)

# Log a CHAPI error messagen
def chapi_error(prefix, msg):
    chapi_log(prefix, msg, logging.ERROR)

# Log a CHAPI info message
def chapi_info(prefix, msg):
    chapi_log(prefix, msg, logging.INFO)

# Log a CHAPI criticial message
def chapi_critical(prefix, msg):
    chapi_log(prefix, msg, logging.CRITICAL)

# Log a CHAPI exception
def chapi_log_exception(prefix, e):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_info = traceback.format_tb(exc_traceback)
    msg = "Exception: %s\n%s" % (e, "".join(tb_info))
    chapi_error(prefix, msg)

# Log an invocation of a method
def chapi_log_invocation(prefix, method, credentials, options, arguments):
    msg = "Invoked %s Options %s Arguments %s" % (method, options, arguments)
    chapi_info(prefix, msg)

# Log the result of an invocation of a method
def chapi_log_result(prefix, method, result):
    msg = "Result from %s: %s" % (method, result)
    chapi_info(prefix, msg)

# Log a potentially auditable event
def chapi_audit(prefix, msg):
    chapi_info(prefix, msg)


