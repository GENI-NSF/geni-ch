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

# Simple persistence-free version of CH for testing/development
from chapi.Clearinghouse import CHv1DelegateBase
from chapi.Exceptions import *
from gcf.geni.util.urn_util import URN
from tools.dbutils import *
from tools.cert_utils import *
from tools.chapi_utils import *
from tools.chapi_log import *
import chapi.Parameters
import tools.CH_constants as CH
import amsoil.core.pluginmanager as pm

# A simple fixed implemntation of the CH API. 
# Only for testing. The real implementation is in CHv1PersistentImplementation

class CHv1Implementation(CHv1DelegateBase):

    # Internal (hard-coded) list of services in internal schema format
    # Meant to mimic a database query return
    services = [
        {"service_type" : CH.SERVICE_AGGREGATE_MANAGER,
         'service_url' : 'https://server.com:12345', 
         'service_cert' : '<certificate>agg1</certificate', 
         'service_name' : 'AGG1',
         'service_description' : 'Agg 1',
         'service_urn' : 'urn:publicid:IDN+server.com+authority+am'
        },
        {"service_type" : CH.SERVICE_AGGREGATE_MANAGER,
         'service_url' : 'https://backuup.com:12345', 
         'service_cert' : '<certificate>agg2</certificate', 
         'service_name' : 'AGG2',
         'service_description' : 'Agg 2',
         'service_urn' : 'urn:publicid:IDN+backup.com+authority+am'
        },
        {"service_type" : CH.SERVICE_SLICE_AUTHORITY,
         'service_url' : 'https://localhost:8001/SA', 
         'service_cert' : '<certificate>foo</certificate', 
         'service_name' : 'CHAPI-SA',
         'service_description' : 'CHAPI Service Authority',
         'service_urn' : 'urn:publicid:IDN+foo.com+authority+sa'
        },
        {"service_type" : CH.SERVICE_SLICE_AUTHORITY,
         'service_url' : 'https://localhost:8002/SA', 
         'service_cert' : '<certificate>bar</certificate', 
         'service_name' : 'CHAPI-SA2',
         'service_description' : 'CHAPI Service Authority (BACKUP)',
         'service_urn' : 'urn:publicid:IDN+bar.com+authority+sa'
        },
        {"service_type" : CH.SERVICE_MEMBER_AUTHORITY,
         'service_url' : 'https://localhost:8001/MA', 
         'service_cert' : '<certificate>foo</certificate', 
         'service_name' : 'CHAPI-MA',
         'service_description' : 'CHAPI Member Authority',
         'service_urn' : 'urn:publicid:IDN+foo.com+authority+ma'
        },
        {"service_type" : CH.SERVICE_MEMBER_AUTHORITY,
         'service_url' : 'https://localhost:8002/MA', 
         'service_cert' : '<certificate>bar</certificate', 
         'service_name' : 'CHAPI-MA2',
         'service_description' : 'CHAPI Member Authority (BACKUP)',
         'service_urn' : 'urn:publicid:IDN+bar.com+authority+ma'
        },
        ]


    def get_version(self, session):
        import flask
        api_versions = \
            {chapi.Parameters.VERSION_NUMBER : flask.request.url_root}
        implementation_info = get_implementation_info(SR_LOG_PREFIX)
        version_info = {"VERSION": chapi.Parameters.VERSION_NUMBER,
                        "IMPLEMENTATION" : implementation_info,
                        "SERVICES": CH.services,
                        "SERVICE_TYPES" : CH.service_types.keys(),
                        "API_VERSIONS" : api_versions,
                        "FIELDS": CH.supplemental_fields}
        return self._successReturn(version_info)

    def lookup_member_authorities(self, client_cert, options, session):
        member_authorities = self.select_services_of_type(self.MA_SERVICE_TYPE)
        return self.select_entries_and_fields(member_authorities, options)

    def lookup_slice_authorities(self, client_cert, options, session):
        member_authorities = self.select_services_of_type(self.SA_SERVICE_TYPE)
        return self.select_entries_and_fields(member_authorities, options)

    def lookup_aggregates(self, client_cert, options, session):
        member_authorities = self.select_services_of_type(self.AGGREGATE_SERVICE_TYPE)
        return self.select_entries_and_fields(member_authorities, options)

    # Take an option 'urns' with a list of urns to lookup
    # Return a dictionary of each URN mapped to the URL of associated URN, or None if not found
    def lookup_authorities_for_urns(self, client_cert, urns, session):
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

        for service in self.services:
            service_urn_obj = URN(urn=service['service_urn'])
            service_authority = service_urn_obj.getAuthority()
            if urn_obj.getType() == 'slice' and \
                    service_urn_obj.getName() == 'sa' and \
                    urn_authority == service_authority:
                authority = service
                break
            elif urn_obj.getType() == 'member' and \
                    service_urn_obj.getName() == 'ma' and \
                    urn_authority == service_authority:
                authority = service
                break

        authority_url = None
        if authority:
            authority_url = authority['service_url']
        return authority_url
            
    def get_trust_roots(self, client_cert, session):
        return []


    def select_services_of_type(self, service_type):
        return [service for service in self.services if service['service_type'] == service_type]

    def select_entries_and_fields(self, services, options):

        print "SERVICES = " + str(services)
        selected_services = services
        match = []
        if options.has_key('match'):
            match = options['match']
        selected_services = [service for service in services if self.match_entry(service, match)]

        print "SELECTED_SERVICES = " + str(selected_services)

        filter = CH.field_mapping.keys() # By default, pick all fields
        if options.has_key('filter'): filter = options['filter']
        filtered_selected_services = [self.filter_entry(service, filter) for service in selected_services]

        print "FILTERED_SELECTED_SERVICES = " + str(filtered_selected_services)

        return filtered_selected_services

    # Determine if a given entry matches given criteria
    # The match is an 'AND' of all provided criteria, with exact match on given value
    def match_entry(self, entry, match):
#        print "ENTRY = " + str(entry)
#        print "MATCH = " + str(match)
        matches = True
        for clause in match:
#            print "CLAUSE = " + str(clause)
            field_name = clause.keys()[0]
            mapped_field_name = convert_internal(field_name, CH.field_mapping)
#            print "FN = " + field_name
#            print "MFN = " + mapped_field_name
            if not entry.has_key(mapped_field_name):
                raise CHAPIv1ArgumentError("No such field in object : " + mapped_field_name)
            field_value = clause[field_name]
            entry_value = entry[mapped_field_name]
#            print "FV = " + str(field_value)
#            print "EV = " + str(entry_value)
            if field_value != entry_value:
                matches = False
                break
        return matches

    # Select the given fields of the entry object as specified by filter
    def filter_entry(self, entry, filter):
#        print "ENTRY = " + str(entry)
#        print "FILTER = " + str(filter)
        filtered = []
        for field_name in entry.keys():
            field_value = entry[field_name]
#            print "FN = " + field_name
#            print "FV = " + str(field_value)
            external_field_name = convert_to_external(field_name, CH.field_mapping)
#            print "EFN = " + external_field_name
            if external_field_name in filter: 
                filtered.append({external_field_name: field_value})
        return filtered

