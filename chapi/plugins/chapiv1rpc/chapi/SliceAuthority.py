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
from tools.cert_utils import *
from tools.chapi_log import *

sa_logger = amsoil.core.log.getLogger('sav1')
xmlrpc = pm.getService('xmlrpc')

# Handler for SA APi. This version only handles the Slice service
class SAv1Handler(HandlerBase):
    def __init__(self):
        super(SAv1Handler, self).__init__(sa_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_exception(SA_LOG_PREFIX, e, {'user': user_email})
        return super(SAv1Handler, self)._errorReturn(e)

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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, {})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'slice_urn' : slice_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_urn' : member_urn})
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

    # Create a record of sliver creation
    # Provide a dictionary of required fields and return a 
    # dictionary of completed fields for new records
    def create_sliver_info(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_sliver_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            results = \
                self._delegate.create_sliver_info(client_cert, \
                                                      credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = \
                    self._guard.protect_results(client_cert, method, \
                                                    credentials, results_value)
                results = self._successReturn(new_results_value)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Delete a sliver_info record of given sliver_urn
    def delete_sliver_info(self, sliver_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'delete_sliver_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'sliver_urn' : sliver_urn})
            results = \
                self._delegate.delete_sliver_info(client_cert, \
                                                      sliver_urn, \
                                                      credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = \
                    self._guard.protect_results(client_cert, method, \
                                                    credentials, results_value)
                results = self._successReturn(new_results_value)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Update the details of a sliver_info record of given sliver_urn
    def update_sliver_info(self, sliver_urn, credentials, options):
        client_cert = self.requestCertificate()
        method = 'update_sliver_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,  \
                                          {'sliver_urn' : sliver_urn})
            results = \
                self._delegate.update_sliver_info(client_cert, \
                                                      sliver_urn, \
                                                      credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = \
                    self._guard.protect_results(client_cert, method, \
                                                    credentials, results_value)
                results = self._successReturn(new_results_value)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Lookup sliver info for given match criteria 
    # return fields in given fillter driteria
    def lookup_sliver_info(self, credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_sliver_info'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options)
            results = \
                self._delegate.lookup_sliver_info(client_cert, \
                                                      credentials, options)
            if results['code'] == NO_ERROR:
                results_value = results['value']
                new_results_value = \
                    self._guard.protect_results(client_cert, method, \
                                                    credentials, results_value)
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,
                                      {'project_urn' : project_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_urn' : member_urn})
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

    ## PROJECT ATTRIBUTE SERVICE methods
        
    # Lookup, add, or remove project attributes
    # of members with respect to given project
    # The name and value of the attribute to add
    #    are fields in the options directionary
    # 'attribute_to_add' : NAME,VALUE
    # 'attribute_to_remove' : NAME
    def lookup_project_attributes(self, project_urn, 
                                 credentials, options):
        client_cert = self.requestCertificate()
        method = 'lookup_project_attributes'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
            results = \
                self._delegate.lookup_project_attributes(client_cert, \
                                                             project_urn, \
                                                             credentials, \
                                                             options)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Add an attribute to a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name, 'attr_value' : attr_value}
    def add_project_attribute(self, \
                                  project_urn, \
                                  credentials, options):
        client_cert = self.requestCertificate()
        method = 'add_project_attribute'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
            results = \
                self._delegate.add_project_attribute(client_cert, \
                                                         project_urn, \
                                                         credentials, \
                                                         options)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # remove an attribute from a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name}
    def remove_project_attribute(self, \
                                     project_urn, \
                                     credentials, options):
        client_cert = self.requestCertificate()
        method = 'remove_project_attribute'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_urn' : project_urn})
            results = \
                self._delegate.remove_project_attribute(client_cert, \
                                                            project_urn, \
                                                            credentials, \
                                                            options)
            return results
        except Exception as e:
            return self._errorReturn(e)




    # Methods for handling pending project / slice requests and invitations
    # Note: Not part of standard Federation API
    
    def create_request(self, context_type, context_id, request_type, request_text, 
                       request_details, credentials, options):
        client_cert = self.requestCertificate()
        method = 'create_request'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type, 
                                           'context_id' : context_id, 
                                           'request_type' : request_type,
                                           'request_text' : request_text,
                                           'request_details' : request_details})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type,
                                           'request_id' : request_id,
                                           'resolution_status' : resolution_status,
                                           'resolution_description' : resolution_description})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'context_type' : context_type, 
                                           'context_id' : context_id,
                                           'status' : status})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type, 
                                           'context_id' : context_id, 
                                           'status' : status})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type,
                                           'context_id' : context_id})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'member_id' : member_id,
                                           'context_type' : context_type,
                                           'context_id' : context_id})
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
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'request_id' : request_id,
                                           'context_type' : context_type})
            return self._delegate.get_request_by_id(client_cert, 
                                                    request_id,
                                                    context_type, 
                                                    credentials, 
                                                    options)
        except Exception as e:
            return self._errorReturn(e)

    def invite_member(self, role, project_id, credentials, options):
        client_cert = self.requestCertificate()
        method = 'invite_member'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'project_id' : project_id,
                                           'role' : role})
            return self._delegate.invite_member(client_cert, role, project_id,
                                                credentials, options)

        except Exception as e:
            return self._errorReturn(e)

    def accept_invitation(self, invite_id, member_id, credentials, options):
        client_cert = self.requestCertificate()
        method = 'accept_invitation'
        try:
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, 
                                                   credentials, options)
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, \
                                          {'invite_id' : invite_id,
                                           'member_id' : member_id})
            return self._delegate.accept_invitation(client_cert, 
                                                    invite_id, member_id,
                                                    credentials, options)

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

    def create_sliver_info(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    def delete_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options):
        raise CHAPIv1NotImplementedError('')

    def update_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options):
        raise CHAPIv1NotImplementedError('')

    def lookup_sliver_info(self, client_cert, credentials, options):
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

    ## PROJECT ATTRIBUTE SERVICE methods
    
    def lookup_project_attributes(self,  \
                                      client_cert, project_urn,  \
                                      credentials, options):
        raise CHAPIv1NotImplementedError('')

    # Add an attribute to a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name, 'attr_value' : attr_value}
    def add_project_attribute(self, \
                                  client_cert, project_urn, \
                                  credentials, options):
        raise CHAPIv1NotImplementedError('')

    # remove an attribute from a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name}
    def remove_project_attribute(self, \
                                     client_cert, project_urn, \
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



    def invite_member(self, client_cert, role, project_id,
                      credentials, options):
        raise CHAPIv1NotImplementedError('')

    def accept_invitation(self, client_cert, invite_id, member_id, 
                          credentials, options):
        raise CHAPIv1NotImplementedError('')
