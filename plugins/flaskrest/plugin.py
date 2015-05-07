#----------------------------------------------------------------------
# Copyright (c) 2011-2015 Raytheon BBN Technologies
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
from amsoil.core import serviceinterface
import amsoil.core.log


rest_logger = amsoil.core.log.getLogger('rest')

# Plugin to load Flask-based REST support

# This is modeled after FlaskXMLRPC
class FlaskREST:
    def __init__(self, flaskapp):
        self._flaskapp = flaskapp

    @ serviceinterface
    def registerREST(self, unique_service_name, handler, endpoint,
                     defaults={},
                     methods=["GET", "POST"]):
        "Register the handler for the endpoint"
        self._flaskapp.app.add_url_rule(endpoint, None, handler,
                                        defaults=defaults,
                                        methods=methods)
#        rest_logger.info("Called FlaskREST.registerREST %s %s %s" % \
#                             (unique_service_name, handler, endpoint))

# Load the Flask REST server
def setup():
    flask_server = pm.getService('rpcserver')
    flask_rest = FlaskREST(flask_server)
    pm.registerService('rest', flask_rest)



