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

from sqlalchemy import *
from chapi.Exceptions import *
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from tools.chapi_log import *
from tools.cert_utils import *
from CHv1Implementation import CHv1Implementation
import tools.CH_constants as CH

# Version of ClearingHouse that works with GPO CH Service Registry tables

class CHv1PersistentImplementation(CHv1Implementation):

    def __init__(self):
        self.db = pm.getService('chdbengine')

    # Get all MAs (authorities of type MA)
    def lookup_member_authorities(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, 
                                         CH.SERVICE_MEMBER_AUTHORITY,
                                         options, session)
        return result

    # Get all SA's (authorities of type SA)
    def lookup_slice_authorities(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, 
                                         CH.SERVICE_SLICE_AUTHORITY,
                                         options, session)
        return result

    # Get all aggregates (authorities of type aggregate)
    def lookup_aggregates(self, client_cert, options, session):
        result = self.lookup_authorities(client_cert, 
                                         CH.SERVICE_AGGREGATE_MANAGER,
                                         options, session)
        return result

    # Lookup all authorities for given service type
    # Add on a service type filter clause before adding any option clauses
    def lookup_authorities(self, client_cert, service_type, options, session):
        selected_columns, match_criteria = unpack_query_options(options, CH.field_mapping)

        q = session.query(self.db.SERVICES_TABLE)
        if service_type is not None:
            if isinstance(service_type, list):
                q = q.filter(self.db.SERVICES_TABLE.c.service_type.in_(service_type))
            else:
                q = q.filter(self.db.SERVICES_TABLE.c.service_type == service_type)
        q = add_filters(q,  match_criteria, self.db.SERVICES_TABLE, 
                        CH.field_mapping, session)
        rows = q.all()

        authorities = [construct_result_row(row, selected_columns, \
                                                CH.field_mapping, session) \
                           for row in rows]

        self.add_service_attributes(rows, authorities, session)

        result = self._successReturn(authorities)

        return result

    # Lookup all services matching given options specification (match and filter)
    def lookup_services(self, client_cert, options, session):
        service_type = None
        if 'match' in options and 'SERVICE_TYPE' in options['match']:
            service_type = options['match']['SERVICE_TYPE']

            # If there are service type names and not codes, change to codes
            # Raise ArgumentError if there are any undefined services
            if not isinstance(service_type, list): 
                service_type = [service_type]
            bad_service_types = []
            new_service_types = []
            for st in service_type:
                new_st = st
                if st in CH.service_types:
                    new_st = CH.service_types[st]
                new_service_types.append(new_st)
                if (isinstance(st, basestring) and \
                        st not in CH.service_types) or \
                        (isinstance(st, int) and \
                             st not in CH.service_types.values()):
                    bad_service_types.append(st)
            service_type = new_service_types
            options['match']['SERVICE_TYPE'] = new_service_types
            if len(bad_service_types) > 0:
                raise CHAPIv1ArgumentError(\
                    "Illegal service type: %s" % bad_service_types)

        services = self.lookup_authorities(client_cert, service_type, options, session)
        return services

    # Add attributes to given services based on associated rows
    def add_service_attributes(self, rows, services, session):


        # Grab the ID's of the services from rows
        # Set up table looking up services by ID
        service_ids = []
        services_by_id = {}
        for i in range(len(rows)):
            row = rows[i]
            service = services[i]
            service_id = row.id
            service_ids.append(service_id)
            services_by_id[service_id] = service

        # Query for all attributes of services in given ID list
        q = session.query(self.db.SERVICE_ATTRIBUTE_TABLE)
        q = \
            q.filter(self.db.SERVICE_ATTRIBUTE_TABLE.c.service_id.in_(service_ids))
        attrib_rows = q.all()

        # Add each attribute to proper service
        for attrib_row in attrib_rows:
            service_id = attrib_row.service_id
            if service_id in services_by_id:
                service = services_by_id[service_id]
                if "_GENI_SERVICE_ATTRIBUTES" not in service:
                    service['_GENI_SERVICE_ATTRIBUTES'] = {}
                service['_GENI_SERVICE_ATTRIBUTES'][attrib_row.name]=attrib_row.value



        
    





