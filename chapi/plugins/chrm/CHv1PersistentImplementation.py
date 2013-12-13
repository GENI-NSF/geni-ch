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

from sqlalchemy import *
from chapi.Exceptions import *
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from tools.chapi_log import *
from tools.cert_utils import *
from CHv1Implementation import CHv1Implementation

# Version of ClearingHouse that works with GPO CH Service Registry tables

class CHv1PersistentImplementation(CHv1Implementation):

    def __init__(self):
        self.db = pm.getService('chdbengine')

    # Get all MAs (authorities of type MA)
    def lookup_member_authorities(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, self.MA_SERVICE_TYPE, 
                                         options, session)
        return result

    # Get all SA's (authorities of type SA)
    def lookup_slice_authorities(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, self.SA_SERVICE_TYPE, 
                                         options, session)
        return result

    # Get all aggregates (authorities of type aggregate)
    def lookup_aggregates(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, 
                                         self.AGGREGATE_SERVICE_TYPE, 
                                         options, session)
        return result

    # Lookup all authorities for given service type
    # Add on a service type filter clause before adding any option clauses
    def lookup_authorities(self, client_cert, service_type, options, session):
        selected_columns, match_criteria = unpack_query_options(options, self.field_mapping)

        q = session.query(self.db.SERVICES_TABLE)
        q = q.filter(self.db.SERVICES_TABLE.c.service_type == service_type)
        q = add_filters(q,  match_criteria, self.db.SERVICES_TABLE, self.field_mapping)
        rows = q.all()

        authorities = [construct_result_row(row, selected_columns, self.field_mapping) for row in rows]

        result = self._successReturn(authorities)

        return result





