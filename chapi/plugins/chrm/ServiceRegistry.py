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
from chapi.Clearinghouse import CHv1Handler
from CHv1PersistentImplementation import CHv1PersistentImplementation
from geni.util.urn_util import URN
from chapi.Exceptions import *
from tools.dbutils import *
from tools.chapi_log import *
import os

# Class for extending the standard CHAPI CH (Clearinghouse i.e. Registry)
# calls for legacy calls for ServiceRegistry: 
#   get_services
#   get_services_of_type(service_type)
#   get_service_by_id(id)
#   get_first_service_of_type(service_type)

class SRv1Handler(CHv1Handler):

    def __init__(self):
        super(SRv1Handler, self).__init__()

    # Return list of all services registered in SR
    def get_services(self):
        try:
            return self._delegate.get_services()
        except Exception as e:
            return self._errorReturn(e)

    # Return list of all services of given type registed in SR
    def get_services_of_type(self, service_type):
        client_cert = self.requestCertificate()
        try:
            return self._delegate.get_services_of_type(client_cert, service_type)
        except Exception as e:
            return self._errorReturn(e)

    # Get all service in service registry by ID
    # Return single row if found, exception otherwise
    def get_service_by_id(self, service_id):
        services = self.get_services()
        if services['code'] != NO_ERROR:
            return services
        for service in services['value']:
            if service['_GENI_SERVICE_ID'] == service_id:
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

    # Take an option 'urns' with a list of urns to lookup
    # Return a dictionary of each URN mapped to the URL of associated URN, or None if not found
    def lookup_authorities_for_urns(self, urns):
        urns_to_authorities = {}
        for urn in urns: 
            urns_to_authorities[urn] = self.lookup_authority_for_urn(urn)
        return self._successReturn(urns_to_authorities)

    # Lookup authority URL for given URN
    # If a slice URN, there may be a project sub-authority: strip this off to match
    def lookup_authority_for_urn(self, urn):
        urn_obj = URN(urn=urn)
        urn_authority = urn_obj.getAuthority()
        if len(urn_authority.split('/')) > 1:
            urn_authority = urn_authority.split('/')[0]
        authority = None

        services = self.get_services()['value']
        for service in services:
            service_urn = service['SERVICE_URN']
            if not service_urn: continue
            service_urn_obj = URN(urn=str(service_urn))
            service_authority = service_urn_obj.getAuthority()
            if urn_obj.getType() == 'slice' and \
                    service_urn_obj.getName() == 'sa' and \
                    urn_authority == service_authority:
                authority = service
                break
            elif urn_obj.getType() == 'user' and \
                    service_urn_obj.getName() == 'ma' and \
                    urn_authority == service_authority:
                authority = service
                break

        authority_url = None
        if authority:
            authority_url = authority['SERVICE_URL']
        return authority_url
            

    # Return list of trust roots for given Federation
    def get_trust_roots(self, client_cert):
        config = pm.getService('config')
        trust_roots = config.get('chapiv1rpc.ch_cert_root')
        pem_files = os.listdir(trust_roots)
        pems = [open(os.path.join(trust_roots, pem_file)).read() for pem_file in pem_files if pem_file != 'CATedCACerts.pem']
        return self._successReturn(pems)

    def get_services_of_type(self, client_cert, service_type):
        method = 'get_services_of_type'
        args = {'service_type' : service_type}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SR_LOG_PREFIX, method, [], {}, args, {'user': user_email})

        options = {'match' : {}, 'filter' : self.field_mapping.keys()}

        services = self.get_services()
        if services['code'] != NO_ERROR:
            return services
        result = [s for s in services['value'] \
                                 if s['SERVICE_TYPE'] == service_type] 

        chapi_log_result(SR_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def get_services(self):
        method = 'get_services'
        chapi_log_invocation(SR_LOG_PREFIX, method, [], {}, {})

        options = {'match' : {}, 'filter' : self.field_mapping.keys()}
        selected_columns, match_criteria = \
            unpack_query_options(options, self.field_mapping)

        session = self.db.getSession()
        q = session.query(self.db.SERVICES_TABLE)
        q = add_filters(q,  match_criteria, self.db.SERVICES_TABLE, \
                            self.field_mapping)
        rows = q.all()
        session.close()

        services = [construct_result_row(row, selected_columns, \
                                             self.field_mapping) \
                        for row in rows]

        # Fill in the service_cert_contents
        if 'SERVICE_CERT' in selected_columns:
            for service in services:
                if service['SERVICE_CERT']:
                    service['SERVICE_CERT'] = \
                        open(service['SERVICE_CERT'], 'r').read()

        result = self._successReturn(services)

        chapi_log_result(SR_LOG_PREFIX, method, result)
        return result

