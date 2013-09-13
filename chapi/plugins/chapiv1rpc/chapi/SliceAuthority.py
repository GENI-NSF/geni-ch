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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
from DelegateBase import DelegateBase
from HandlerBase import HandlerBase
from Exceptions import *

sa_logger = amsoil.core.log.getLogger('sav1')
xmlrpc = pm.getService('xmlrpc')

# Handler for SA APi. This version only handles the Slice service
class SAv1Handler(HandlerBase):
    def __init__(self):
        super(SAv1Handler, self).__init__(sa_logger)

    ## SLICE SERVICE methods

    # This call is unprotected: no checking of credentials
    # Return version information about this SA including what
    # services are provided and underlying object model
    def get_version(self):
        try:
            return self._delegate.get_version()
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Create a slice given provided options and authorized by client_cert
    # and given credentials
    def create_slice(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_slice'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.create_slice(client_cert, credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Lookup slices with filters and match criterial given in options
    # Authorized by client cert and credentials
    def lookup_slices(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_slices'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, {})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.lookup_slices(client_cert, credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Update slice with fields specified in given options for given slice
    # Authorized by client cert and credentials
    def update_slice(self, slice_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'update_slice'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.update_slice(client_cert, slice_urn, \
                                                      credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # This call is protected
    # Get credentials for given user with respect to given slice
    # Authorization based on client cert and givencredentiabls
    def get_credentials(self, slice_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_credentials'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.get_credentials(client_cert, slice_urn, \
                                                         credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    ## SLICE MEMBER SERVICE methods
    
    # Modify slice membership, adding, removing and changing roles
    # of members with respect to given slice
    # The list of members_to_add, members_to_remove, members_to_modify
    # are fields in the options directionary
    # 'members_to_add' : List of {URN : ROLE} dictionaries
    # 'members_to_remove' : List of URNs
    # 'members_to_modify' : List of {URN : ROLE} dictionaries
    def modify_slice_membership(self, slice_urn, 
                                    credentials, options):
        client_cert = self.requestCertificate()
        method = 'modify_slice_membership'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
            results = self._delegate.modify_slice_membership(\
                client_cert, \
                    slice_urn, \
                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup members of given slice and their roles within that slice
    def lookup_slice_members(self, slice_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_slice_members'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.lookup_slice_members(client_cert, \
                                                              slice_urn, \
                                                              credentials, \
                                                              options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup slices to which member belongs and their roles
    def lookup_slices_for_member(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_slices_for_member'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_urn' : member_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = \
                self._delegate.lookup_slices_for_member(client_cert, \
                                                             member_urn, \
                                                             credentials, \
                                                             options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    ## SLIVER INFO SERVICE methods
        
    # Associate an aggregate as having sliver information in a given 
    # slice. Expected to be called by an aggregate as an asynchronous 
    # (not critical-path) part of the resource allocation process.
    def register_aggregate(self, slice_urn, aggregate_url, credentials, options):
        client_cert = self.requestCertificate()
        method = 'register_aggregate'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn,
                                           'aggregate_url' : aggregate_url})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.register_aggregate(client_cert, \
                                                            slice_urn, \
                                                            aggregate_url, \
                                                            credentials, \
                                                            options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Dis-associate an aggregate as having sliver information in a given slice
    # Expected to be called by the aggregate as an asynchronous 
    # (non-critical path) part of the resource de-allocation process
    def remove_aggregate(self, slice_urn, aggregate_url, credentials, options):
        client_cert = self.requestCertificate()
        method = 'remove_aggregate'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn,
                                           'aggregate_url' : aggregate_url})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.remove_aggregate(client_cert, \
                                                          slice_urn, \
                                                          aggregate_url, \
                                                          credentials, \
                                                          options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Provide a list of URNs of all aggregates that have been registered
    # as having resources allocated with a given slice
    # NB: This list is not definitive in that the aggregate maynot have 
    # called register_aggregate call, and that the slivers may no longer
    # be at that aggregate. But it is provided as a convenience for tools to 
    # know where to go for sliver information (rather than querying 
    # every aggregate in the CH)
    def lookup_slice_aggregates(self, slice_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_slice_aggregates'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.lookup_slice_aggregates(client_cert, \
                                                              slice_urn, \
                                                              credentials, \
                                                              options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    ## PROJECT SERVICE methods

    # Create project with given details in options
    def create_project(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_project'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.create_project(client_cert, \
                                                        credentials, \
                                                        options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)


    # Lookup project detail for porject matching 'match' option
    # returning fields in 'filter' option
    def lookup_projects(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_projects'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.lookup_projects(client_cert, \
                                                         credentials, \
                                                         options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Update fields in given project object specified in options
    def update_project(self, project_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'update_project'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,
                                      {'project_urn' : project_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.update_project(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

        pass

    ## PROJECT MEMBER SERVICE methods
    
    # Modify project membership, adding, removing and changing roles
    # of members with respect to given project
    # The list of members_to_add, members_to_remove, members_to_modify
    # are fields in the options directionary
    # 'members_to_add' : List of {URN : ROLE} dictionaries
    # 'members_to_remove' : List of URNs
    # 'members_to_modify' : List of {URN : ROLE} dictionaries
    def modify_project_membership(self, project_urn, 
                                      credentials, options):
        client_cert = self.requestCertificate()
        method = 'modify_project_membership'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.modify_project_membership(\
                client_cert, \
                    project_urn, \
                    credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup members of given project and their roles within that project
    def lookup_project_members(self, project_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_project_members'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = self._delegate.lookup_project_members(client_cert, \
                                                                project_urn, \
                                                                credentials, \
                                                                options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup projects to which member belongs and their roles
    def lookup_projects_for_member(self, member_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_projects_for_member'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_urn' : member_urn})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            results = \
                self._delegate.lookup_projects_for_member(client_cert, \
                                                             member_urn, \
                                                             credentials, \
                                                             options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = self._guard.protect_results(client_cert, method, credentials, results_value)
                results = self._successReturn(new_results_value)

            return results
        except Exception as e:
            return self._errorReturn(e)

    # Methods for handling pending project / slice requests
    # Note: Not part of standard Federation API
    
    def create_request(self, context_type, context_id, request_type, request_text, 
                       request_details, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_request'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type, 
                                           'context_id' : context_id, 
                                           'request_type' : request_type,
                                           'request_text' : request_text,
                                           'request_details' : request_details})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.create_request(client_cert, \
                                                     context_type, context_id, \
                                                     request_type, request_text, \
                                                     request_details, credentials, options)
        except Exception as e:
            return self._errorReturn(e)


    def resolve_pending_request(self, context_type, request_id, \
                                    resolution_status, resolution_description,  \
                                    credentials, options):
        client_cert = self.requestCertificate()
        method = 'resolve_pending_request'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type,
                                           'request_id' : request_id,
                                           'resolution_status' : resolution_status,
                                           'resolution_description' : resolution_description})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.resolve_pending_request(client_cert, \
                                                              context_type, request_id, \
                                                              resolution_status, \
                                                             resolution_description, \
                                                             credentials, options)
        except Exception as e:
            return self._errorReturn(e)

    def get_requests_for_context(self, context_type, context_id, status, \
                                     credentials, options):
        print "SA.get_requests_for_context : %s %s %s" % (context_type, context_id, status)
        client_cert = self.requestCertificate()
        method = 'get_requests_for_context'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type, 
                                           'context_id' : context_id,
                                           'status' : status})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.get_requests_for_context(client_cert, \
                                                               context_type, context_id,\
                                                               status, \
                                                               credentials, options)
        except Exception as e:
            return self._errorReturn(e)


    def get_requests_by_user(self, member_id, context_type, context_id, status, \
                                     credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_requests_by_user'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type, 
                                           'context_id' : context_id, 
                                           'status' : status})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.get_requests_by_user(client_cert, \
                                                           member_id, 
                                                           context_type, context_id,\
                                                           status, \
                                                           credentials, options)
        except Exception as e:
            return self._errorReturn(e)

    def get_pending_requests_for_user(self, member_id, context_type, context_id, \
                                     credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_pending_requests_for_user'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type,
                                           'context_id' : context_id})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.get_pending_requests_for_user(client_cert, \
                                                                    member_id, 
                                                                    context_type, \
                                                                    context_id,\
                                                                    credentials, options)
        except Exception as e:
            return self._errorReturn(e)

    def get_number_of_pending_requests_for_user(self, member_id, \
                                                    context_type, context_id, \
                                                    credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_number_of_pending_requests_for_user'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type,
                                           'context_id' : context_id})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.get_number_of_pending_requests_for_user(client_cert, 
                                                                          member_id, 
                                                                          context_type, 
                                                                          context_id,
                                                                          credentials, 
                                                                          options)
        except Exception as e:
            return self._errorReturn(e)

    def get_request_by_id(self, request_id, context_type, credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_request_by_id'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'request_id' : request_id,
                                           'context_type' : context_type})
            client_cert, options = self._guard.adjust_client_identity(client_cert, 
                                                                     credentials, options)
            return self._delegate.get_request_by_id(client_cert, 
                                                    request_id,
                                                    context_type, 
                                                    credentials, 
                                                    options)
        except Exception as e:
            return self._errorReturn(e)


# Base class for implementing the SA Slice interface. Must be
# implemented in a derived class, and that derived class
# must call setDelegate on the handler
class SAv1DelegateBase(DelegateBase):
    
    ## SLICE SERVICE methods

    def __init__(self):
        super(SAv1DelegateBase, self).__init__(sa_logger)
    
    def get_version(self):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def create_slice(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_slices(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def update_slice(self, client_cert, slice_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def get_credentials(self, client_cert, slice_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    ## SLICE MEMBER SERVICE methods
    
    def modify_slice_membership(self,  \
                                    client_cert, slice_urn, 
                                    credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_slice_members(self, \
                                 client_cert, slice_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_slices_for_member(self, \
                                     client_cert, member_urn, \
                                     credentials, options):
        raise CHAPIv1NotImplementedError('')


    ## SLIVER INFO SERVICE methods
        
    def register_aggregate(self, client_cert, \
                               slice_urn, aggregate_url, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def remove_aggregate(self, client_cert, \
                             slice_urn, aggregate_url, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_slice_aggregates(self, client_cert, \
                           slice_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    
    ## PROJECT SERVICE methods

    def create_project(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_projects(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def update_project(self, client_cert, project_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')

    ## PROJECT MEMBER SERVICE methods
    
    def modify_project_membership(self,  \
                                    client_cert, project_urn, 
                                    credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_project_members(self, \
                                 client_cert, project_urn, \
                                   credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_projects_for_member(self, \
                                     client_cert, member_urn, \
                                     credentials, options):
        raise CHAPIv1NotImplementedError('')

    # Request handling methods

    def create_request(self, client_cert, context_type, \
                           context_id, request_type, request_text, \
                           request_details, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def resolve_pending_request(self, client_cert, context_type, request_id, \
                                    resolution_status, resolution_description,  \
                                    credentials, options):
        raise CHAPIv1NotImplementedError('')

    def get_requests_for_context(self, client_cert, context_type, \
                                 context_id, status, \
                                 credentials, options):
        raise CHAPIv1NotImplementedError('')

    def get_requests_by_user(self, client_cert, member_id, context_type, \
                                 context_id, status, \
                                 credentials, options):
        raise CHAPIv1NotImplementedError('')

    def get_pending_requests_for_user(self, client_cert, member_id, \
                                          context_type, context_id, \
                                          credentials, options):
        raise CHAPIv1NotImplementedError('')

    def get_number_of_pending_requests_for_user(self, client_cert, member_id, \
                                                    context_type, context_id, \
                                                    credentials, options):
        raise CHAPIv1NotImplementedError('')

    def get_request_by_id(self, client_cert, request_id, context_type, \
                              credentials, options):
        raise CHAPIv1NotImplementedError('')



