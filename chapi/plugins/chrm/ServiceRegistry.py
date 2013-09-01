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

from chapi.Clearinghouse import CHv1Handler
from CHv1PersistentImplementation import CHv1PersistentImplementation
from chapi.Exceptions import *
from tools.dbutils import *

# Class for extending the standard CHAPI CH (Clearinghouse i.e. Registry)
# calls for legacy calls for ServiceRegistry: 
#   get_services
#   get_services_of_type(service_type)
#   get_service_by_id(id)
#   get_first_service_of_type(service_type)

class SRv1Handler(CHv1Handler):

    def __init__(self):
        super(SRv1Handler, self).__init__()

    # Return list of all services registed in SR
    def get_services(self):
        try:
            return self._delegate.get_services()
        except Exception as e:
            return self._errorReturn(e)

    # Return list of all services of given type registed in SR
    def get_services_of_type(self, service_type):
        try:
            return self._delegate.get_services_of_type(service_type)
        except Exception as e:
            return self._errorReturn(e)

    # Get all service in service registry by ID
    # Return single row if found, exception otherwise
    def get_service_by_id(self, service_id):
        services = self.get_services()
        if services['code'] != NO_ERROR:
            return services
        for service in services['value']:
            if service['SERVICE_ID'] == service_id:
                return self._successReturn(service)
        return self._errorReturn(\
            CHAPIv1DatabaseError("No service of ID %d found" % service_id))

    def get_first_service_of_type(self, service_type):
        sot = self.get_services_of_type(service_type)
        if sot['code'] != NO_ERROR:
            return sot
        services = sot['value']
        if len(services) > 0:
            return self._successReturn(services[0])
        return self._errorReturn(\
            CHAPIv1DatabaseError("No services of type %d found" % service_type))

class SRv1Delegate(CHv1PersistentImplementation):

    def __init__(self):
        super(SRv1Delegate, self).__init__()

    def get_services_of_type(self, service_type):
        options = {'match' : {}, 'filter' : self.field_mapping.keys()}
        return self.lookup_authorities(service_type, options)

    def get_services(self):
        options = {'match' : {}, 'filter' : self.field_mapping.keys()}
        selected_columns, match_criteria = \
            unpack_query_options(options, self.field_mapping)

        session = self.db.getSession()
        q = session.query(self.db.SERVICES_TABLE)
        q = add_filters(q,  match_criteria, self.db.SERVICES_TABLE, \
                            self.field_mapping)
        rows = q.all()
        session.close()

        authorities = [construct_result_row(row, selected_columns, \
                                                self.field_mapping) \
                           for row in rows]

        return self._successReturn(authorities)

