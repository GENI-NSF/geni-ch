from sqlalchemy import *
from chapi.Exceptions import *
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from CHv1Implementation import CHv1Implementation

class CHv1PersistentImplementation(CHv1Implementation):

    def __init__(self):
        self.db = pm.getService('chdbengine')

    # Get all MAs (authorities of type MA)
    def get_member_authorities(self, options):
        return self.lookup_authorities(self.MA_SERVICE_TYPE, options)

    # Get all SA's (authorities of type SA)
    def get_slice_authorities(self, options):
        return self.lookup_authorities(self.SA_SERVICE_TYPE, options)

    # Get all aggregates (authorities of type aggregate)
    def get_aggregates(self, options):
        return self.lookup_authorities(self.AGGREGATE_SERVICE_TYPE, options)

    # Lookup all authorities for given service type
    # Add on a service type filter clause before adding any option clauses
    def lookup_authorities(self, service_type, options):

        selected_columns, match_criteria = unpack_query_options(options, self.field_mapping)

        session = self.db.getSession()
        q = session.query(self.db.SERVICES_TABLE)
        q = q.filter(self.db.SERVICES_TABLE.c.service_type == service_type)
        q = add_filters(q,  match_criteria, self.db.SERVICES_TABLE, self.field_mapping)
        rows = q.all()
        session.close()

        authorities = [construct_result_row(row, selected_columns, self.field_mapping) for row in rows]

        return self._successReturn(authorities)




