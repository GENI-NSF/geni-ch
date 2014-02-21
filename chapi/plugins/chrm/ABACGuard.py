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

from CHDatabaseEngine import CHDatabaseEngine
import amsoil.core.log
import amsoil.core.pluginmanager as pm
from sqlalchemy import *
from sqlalchemy.orm import aliased
from sqlalchemy.orm import mapper
from tools.cert_utils import *
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
import types
from ABAC import *
from tools.SpeaksFor import determine_speaks_for
from tools.ABACManager import ABACManager
from ArgumentCheck import *
from tools.geni_constants import *
from tools.geni_utils import *
from tools.guard_utils import *
import amsoil.core.pluginmanager as pm
from tools.chapi_log import *
from tools.mapped_tables import MemberAttribute
import logging
from tools import MA_constants

logger = amsoil.core.log.getLogger('ABAC')


# Pre-processor for method invocations
class InvocationCheck(object):

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    # Return dictionary of {subject_type : subjects}
    def validate_arguments(self, client_cert, method, credentials, \
                               options, arguments, session):
        # Method-specific logic
        return None

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/arguments passed to the call
    # and subjects extracted from validate_arguments call
    def authorize_call(self, client_cert, method, credentials, options, \
                           arguments, subjects, session ):
        raise CHAPIv1NotImplementedError("Abstract Base class: InvocationCheck")

    # Validate arguments and check authorization
    def validate(self, client_cert, method, credentials, options, 
                 arguments, session):
        subjects = self.validate_arguments(client_cert, method, credentials, \
                                               options, arguments, session)
        self.authorize_call(client_cert, method, credentials, \
                                options, arguments, subjects, session)

# Class that determines if the caller has the right to invoke a given method on all
# the subjects of a given method invocation
class SubjectInvocationCheckOrig(InvocationCheck):

    def __init__(self, policies, attribute_extractors,
                 subject_extractor, pass_empty_subject = False):
        self._policies = policies
        self._attribute_extractors = attribute_extractors
        if attribute_extractors and not isinstance(attribute_extractors, list): 
            self._attribute_extractors = [attribute_extractors]
        self._subject_extractor = subject_extractor
        self._pass_empty_subject = pass_empty_subject
        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")

    # Check that there are subjects in the arguments if required
    # Store the list of subjects for later authorization
    def validate_arguments(self, client_cert, method, credentials, \
                               options, arguments, session):
        subjects = {}
        if self._subject_extractor:
            subjects = self._subject_extractor(options, arguments, session)
#            if not subjects or len(subjects) == 0:
#                raise CHAPIv1ArgumentError("No subjects supplied to call %s" % method);
            if subjects and len(subjects) > 1:
                raise CHAPIv1ArgumentError("Can't provide mixture of subject types for call %s: %s" % \
                                               (method, subjects.keys()))
            if subjects and len(subjects) > 0:
                subject_type = subjects.keys()[0]
                subjects_of_type = subjects[subject_type]
                ensure_valid_urns(subject_type, subjects_of_type, session)

#        chapi_debug('ABACGuard', 'method %s SUBJECTS = %s' % (method,subjects))
        return subjects

    def load_policies(self, abac_manager, subject_name):
        for policy in self._policies:
            if policy.find("$SUBJECT") >= 0:
                if not subject_name:
                    continue
                policy = policy.replace("$SUBJECT", subject_name)
            abac_manager.register_assertion(policy)

        

    # If there are subjects
    #    For each subject prove AUTHORITY.MAY_$method(SUBJECT)<-CALLER
    # If there are no subjects (and this is allowed by validate_arguments)
    #    Prove AUTHORITYMAY_$method<-CALLER
    def authorize_call(self, client_cert, method, credentials, options, \
                           arguments, subjects, session):
        abac_manager =  ABACManager(certs_by_name = {"CALLER" : client_cert}, 
                                    cert_files_by_name = {"ME" : self.cert_file}, 
                                    key_files_by_name = {"ME" : self.key_file},
                                    manage_context = False)
        abac_manager._verbose = True

        client_urn = get_urn_from_cert(client_cert)

        # Gather context-free assertions for caller
        if lookup_operator_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_OPERATOR<-CALLER")
        if lookup_pi_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_PI<-CALLER")
        abac_manager.register_assertion("ME.IS_%s<-CALLER" % flatten_urn(client_urn))
        if lookup_authority_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_AUTHORITY<-CALLER")

#        chapi_info("SUBJECTS", "%s" % subjects)
        if subjects:

            subject_type = subjects.keys()[0]
            subjects_of_type = subjects[subject_type]
            if not isinstance(subjects_of_type, list) : 
                subjects_of_type = [subjects_of_type]
            # empty subject list means not returning anything, so okay          
            if not subjects_of_type and self._pass_empty_subject:
                return

            # Register assertions for the user 
            if self._attribute_extractors:
#                chapi_debug('ABACGuard', "Method %s Registering assertions for callers %s, subjects %s" % (method, client_urn, subjects_of_type))
                for attribute_extractor in self._attribute_extractors:
                    attribute_extractor(client_urn, subjects_of_type, \
                                        subject_type, options, arguments, abac_manager,
                                        session)

            # Register policies relative to the subjects
            # And try to prove that the user may call the method, 
            # given the policies
            # About who can call the method and the attributes of the caller
            for subject in subjects_of_type:
#                print "SUBJECT = " + subject
                subject_name = flatten_urn(subject)

                self.load_policies(abac_manager, subject_name)

                queries = [
                    "ME.MAY_%s_%s<-CALLER" % (method.upper(), subject_name), 
                    "ME.MAY_%s<-CALLER" % method.upper()
                    ]

                one_succeeded = False
                for query in queries:
                    ok, proof = abac_manager.query(query)
                    if abac_manager._verbose:
                        chapi_audit_and_log("ABAC", "Testing ABAC query %s OK = %s" % (query, ok), logging.DEBUG)
                    if ok:
                        one_succeeded = True
                        break

                if not one_succeeded:
                    template = "Caller not authorized to call method %s " + \
                        "with options %s arguments %s queries %s"
                    raise CHAPIv1AuthorizationError(template % \
                            (method, options, arguments, queries));
                    
        else:
            self.load_policies(abac_manager, None)


            query ="ME.MAY_%s<-CALLER" % method.upper()
            ok, proof = abac_manager.query(query)
            if abac_manager._verbose:
                chapi_audit_and_log("ABAC", "Testing ABAC query %s OK = %s" % (query, ok), logging.DEBUG)
            if not ok:
                template = "Caller not authorized to call method %s " + \
                    "with options %s arguments %s query %s"
                raise CHAPIv1AuthorizationError(template % \
                        (method, options, arguments, query));

# Class that determines if the caller has the right to invoke a given method on all
# the subjects of a given method invocation
class SubjectInvocationCheck(InvocationCheck):

    def __init__(self, policies, assertions, pass_empty_subject = False):
        self._policies = policies
        if not policies: self._policies = []
        if policies and not isinstance(policies, list):
            self._policies = [policies]

        self._assertions = assertions
        if not assertions: self._assertions = []
        if assertions and not isinstance(assertions, list):
            self._assertions = [assertions]

        self._pass_empty_subject = pass_empty_subject
        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")
        self._bindings = {}

        # Gather all required bindings
        for assertion in self._assertions:
            self._gather_bindings(assertion)
        for policy in self._policies:
            self._gather_bindings(policy)

    # All recognized binding types (variables that can be
    # substituted in assertions and policies)
    RECOGNIZED_BINDINGS = ["$ROLE", "$SLICE", "$PROJECT", \
                               "$MEMBER", "$SELF", \
                               "$SHARES_SLICE", "$SHARES_PROJECT", \
                               "$PROJECT_LEAD", "$PROJECT_ADMIN", \
                               "$SEARCHING_BY_EMAIL", \
                               "$SEARCHING_FOR_PROJECT_LEAD_BY_UID", \
                               "$PENDING_REQUEST_TO_MEMBER", \
                               "$REQUEST_ROLE", \
                               "$REQUESTOR" ]

    def _gather_bindings(self, template):
        for recognized_binding in SubjectInvocationCheck.RECOGNIZED_BINDINGS:
            if template.find(recognized_binding) > 0:
                if recognized_binding not in self._bindings:
                    self._bindings[recognized_binding] = None

    def _compute_subjects(self, options, arguments, session):
        urns, label = self._compute_slice_subjects(options, arguments, session)
        if not urns:
            urns, label = \
                self._compute_project_subjects(options, arguments, session)
        if not urns:
            urns, label = \
                self._compute_member_subjects(options, arguments, session)
        if not urns:
            urns, label = \
                self._compute_request_subjects(options, arguments, session)
        if urns and not isinstance(urns, list): urns = [urns]
        if urns:
            return {label : urns}
        else:
            return None

    def _compute_slice_subjects(self, options, arguments, session):
        urns = None
        if 'match' in options:
            match_option = options['match']
            # Pulling slice out of match
            if 'SLICE_URN' in match_option:
                urns = match_option['SLICE_URN']
            elif 'SLICE_UID' in match_option:
                slice_uids = match_option['SLICE_UID']
                if not isinstance(slice_uids, list): slice_uids = [slice_uids]
                urns = convert_slice_uid_to_urn(slice_uids, session)
            elif 'SLIVER_INFO_SLICE_URN' in match_option:
                urns = match_option['SLIVER_INFO_SLICE_URN']
            elif 'SLIVER_INFO_URN' in match_option:
                sliver_urns = match['SLIVER_INFO_URN']
                if not isinstance(sliver_urns, list): 
                    sliver_urns = [sliver_urns]
                    urns = \
                        [lookup_slice_urn_for_sliver_urn(sliver_urn, session)\
                             for sliver_urn in sliver_urns]
        elif 'slice_urn' in arguments:
            urns = arguments['slice_urn']
        elif 'fields' in options and 'SLICE_URN' in options['fields']:
            urns = options['fields']['SLICE_URN']
        elif 'fields' in options and \
                'SLIVER_INFO_SLICE_URN' in options['fields']:
            urns = options['fields']['SLIVER_INFO_SLICE_URN']
        elif 'sliver_urn' in arguments:
            db = pm.getService('chdbengine')
            q = session.query(db.SLIVER_INFO_TABLE.c.slice_urn)
            q = q.filter(db.SLIVER_INFO_TABLE.c.sliver_urn == \
                             arguments['sliver_urn'])
            rows = q.all()
            if len(rows) > 0:
                urns = rows[0].slice_urn
        elif 'context_type' in arguments and 'context_id' in arguments and \
                arguments['context_type'] == SLICE_CONTEXT:
            if arguments['context_id'] != '':
                slice_uid = arguments['context_id']
                urns = convert_slice_uid_to_urn(slice_uid, session)
        elif 'attributes' in arguments and \
                'SLICE' in arguments['attributes']:
            slice_uid = attributes['SLICE']
            urns = convert_slice_uid_to_urn(slice_uid, session)

        chapi_info("C_S_S", "%s %s %s" % (options, arguments, urns))
        return urns, "SLICE_URN"

    def _compute_project_subjects(self, options, arguments, session):
        urns = None
        if 'match' in options:
            match_option = options['match']
            # Pulling project out of match
            if "PROJECT_URN" in match_option:
                urns = match_option['PROJECT_URN']
            elif "PROJECT_UID" in match_option:
                project_uids = match_option['PROJECT_UID']
                if not isinstance(project_uids, list): 
                    project_uids = [project_uids]
                urns = convert_project_uid_to_urn(project_uids, session)
            elif "_GENI_PROJECT_UID" in match_option:
                project_uids = match_option['_GENI_PROJECT_UID']
                if not isinstance(project_uids, list): 
                    project_uids = [project_uids]
                urns = convert_project_uid_to_urn(project_uids, session)
        elif 'fields' in options and 'PROJECT_NAME' in options['fields']:
            project_name = options['fields']['PROJECT_NAME']
            config = pm.getService('config')
            authority = config.get('chrm.authority')
            urns = to_project_urn(authority, project_name)
        elif 'project_urn' in arguments:
            urns = arguments['project_urn']
        elif 'fields' in options and \
                'SLICE_PROJECT_URN' in options['fields']:
            urns = options['fields']['SLICE_PROJECT_URN']
        elif 'project_id' in arguments:
            project_id = arguments['project_id']
            urns = convert_project_uid_to_urn(project_id, session)
        elif 'context_type' in arguments and 'context_id' in arguments and \
            arguments['context_type'] == PROJECT_CONTEXT:
            if arguments['context_id'] != '':
                project_uid = arguments['context_id']
                urns = convert_project_uid_to_urn(project_uid, session)
        elif 'attributes' in arguments and \
                'PROJECT' in arguments['attributes']:
            project_uid = attributes['SLICE']
            urns = convert_project_uid_to_urn(project_uid, session)

        return urns, "PROJECT_URN"

    def _compute_member_subjects(self, options, arguments, session):
        urns = None
        if 'match' in options:
            match_option = options['match']
            # Pulling member out of match
            if "MEMBER_URN" in match_option:
                urns = match_option['MEMBER_URN']
            elif "MEMBER_UID" in match_option:
                member_uids = match_option['MEMBER_UID']
                if not isinstance(member_uids, list): 
                    member_uids = [member_uids]
                urns = convert_member_uid_to_urn(member_uids, session)
            elif '_GENI_KEY_MEMBER_UID' in match_option:
                member_uids = match_option['_GENI_KEY_MEMBER_UID']
                if not isinstance(member_uids, list): 
                    member_uids =[member_uids]
                urns = convert_member_uid_to_urn(member_uids, session)
            elif 'MEMBER_EMAIL' in match_option:
                member_emails = match_option['MEMBER_EMAIL']
                member_uids = \
                    convert_member_email_to_uid(member_emails, session)
                urns = \
                    convert_member_uid_to_urn(member_uids, session)
            elif '_GENI_MEMBER_EPPN' in match_option:
                member_eppns = match_option['_GENI_MEMBER_EPPN']
                member_uids = convert_member_eppn_to_uid(member_eppns, session)
                urns = convert_member_uid_to_urn(member_uids, session)
            elif 'KEY_MEMBER' in match_option:
                urns = match_option['KEY_MEMBER']
            elif '_GENI_KEY_MEMBER_UID' in match_option:
                key_id = arguments['key_id']
                q = session.query(db.SSH_KEY_TABLE.c.member_id)
                q = q.filter(db.SSH_KEY_TABLE.c.id == key_id)
                rows = q.all()
                if len(rows) != 1:
                    raise CHAPIv1ArgumentError("No key with given ID %s" % \
                                                   key_id)
                member_id = rows[0].member_id
                urns = convert_member_uid_to_urn(member_id, session)
            elif 'SLIVER_INFO_CREATOR_URN' in match_option:
                urns = match_option['SLIVER_INFO_CREATOR_URN']
        elif 'member_urn' in arguments:
            urns = arguments['member_urn']
        elif 'member_id' in arguments:
            member_id = arguments['member_id']
            urns = convert_member_uid_to_urn(member_id, session)
        elif 'key_id' in arguments:
            key_id = arguments['key_id']
            q = session.query(db.SSH_KEY_TABLE.c.member_id)
            q = q.filter(db.SSH_KEY_TABLE.c.id == key_id)
            rows = q.all()
            if len(rows) != 1:
                raise CHAPIv1ArgumentError("No key with given ID %s" % key_id)
            member_id = rows[0].member_id
            urns = convert_member_uid_to_urn(member_id, session)
        elif 'principal' in arguments:
            principal_uid = arguments['principal']
            urns = convert_member_uid_to_urn(principal_uid, session)
        elif 'user_id' in arguments:
            user_uid = arguments['user_id']
            urns = convert_member_uid_to_urn(user_uid, session)
        elif 'context_type' in arguments and 'context_id' in arguments and \
                arguments['context_type'] == MEMBER_CONTEXT:
            member_uid = arguments['context_id']
            urns = convert_member_uid_to_urn(member_uid, session)
        elif 'attributes' in arguments and \
                'MEMBER' in arguments['attributes']:
            member_uid = attributes['MEMBER']
            urns = convert_member_uid_to_urn(member_uid, session)

        return urns, "MEMBER_URN"

    def _compute_request_subjects(self, options, arguments, session):
        if 'request_id' in arguments:
            request_id = arguments['request_id']
            return 'REQUEST_ID', request_id
        return None, None

    def _generate_bindings(self, caller_urn, subject_type, subject, \
                               options, arguments, session):
        chapi_info("GB","BINDINGS = %s SUBJECT = %s" % (self._bindings, subject))
        for binding in self._bindings:
            value = None
            if binding == "$ROLE":
                if subject_type == "SLICE_URN":
                    rows = get_slice_role_for_member(caller_urn, \
                                                         subject, session)
                elif subject_type == "PROJECT_URN":
                    rows = get_project_role_for_member(caller_urn, \
                                                            subject, session)
                else:
                    rows = [] # Can't compute role for other than slice/project
                for row in rows:
                    role = row.role
                    value = attribute_type_names[role]
                    break
            if binding == "$SLICE":
                if subject_type == "SLICE_URN":
                    value = subject
            if binding == "$PROJECT":
                if subject_type == "PROJECT_URN":
                    value = subject
            if binding == "$MEMBER":
                if subject_type == "MEMBER_URN":
                    value = subject
            if binding == "$SELF":
                value = caller_urn
            if binding == "$SHARES_SLICE":
                if subject_type == "MEMBER_URN" and \
                        shares_slice(caller_urn, subject, session):
                    value = "SHARES_SLICE"
            if binding == "$SHARES_PROJECT":
                if subject_type == "MEMBER_URN" and \
                        shares_project(caller_urn, subject, session):
                    value = "SHARES_PROJECT"
            if binding == "$PROJECT_LEAD":
                if subject_type == "MEMBER_URN" and \
                        has_role_on_some_project(subject, LEAD_ATTRIBUTE,\
                                                     session):
                    value = "PROJECT_LEAD"
            if binding == "$PROJECT_ADMIN":
                if subject_type == "MEMBER_URN" and \
                        has_role_on_some_project(subject, ADMIN_ATTRIBUTE,\
                                                     session):
                    value = "PROJECT_ADMIN"
            if binding == "$SEARCHING_BY_EMAIL":
                if 'match' in options and 'MEMBER_EMAIL' in options['match']:
                    value = "SEARCHING_BY_EMAIL"
            if binding == "$SEARCHING_FOR_PROJECT_LEAD_BY_UID":
                if 'match' in options and 'MEMBER_UID' in options['match'] \
                        and has_role_on_some_project(subject, LEAD_ATTRIBUTE,\
                                                         session):
                    value = "SEARCHING_FOR_PROJECT_LEAD_BY_UID"
            if binding == "$PENDING_REQUEST_TO_MEMBER":
                if subject_type == "MEMBER_URN" and \
                        has_pending_request_on_project_lead_by(subject, \
                                                                   caller_urn,\
                                                                   session):
                    value = "PENDING_REQUEST_TO_MEMBER"
            if binding == "$REQUEST_ROLE":
                if subject_type == "REQUEST_ID":
                    project_urn = \
                        get_project_request_project_urn(subject, session)
                    if project_urn is not None:
                        rows = get_project_role_for_member(caller_urn, \
                                                               project_urn, \
                                                               session)
                        if len(rows) > 0:
                            role = rows[0].role
                            value = attribute_type_names[role]
            if binding == "$REQUESTOR":
                if subject_type == "REQUEST_ID":
                    requestor_urn = \
                        get_project_request_requestor_urn(subject, session)
                    if caller_urn == requestor_urn:
                        value = "REQUESTOR"

            if value:
                self._bindings[binding]=value

        chapi_info("GB","BINDINGS = %s SUBJECT = %s" % (self._bindings, subject))
    def _assert_bound_statements(self, abac_manager, statements):
        for stmt in statements:
            orig_stmt = stmt
            for binding_name, binding_value in self._bindings.items():
                if binding_value:
                    stmt = stmt.replace(binding_name, flatten_urn(binding_value))
            if stmt.find('$')<0:
                abac_manager.register_assertion(stmt)
            else:
#                chapi_info("ABACGuard", 
#                           "Cannot assert statement due to unbound variables: %s => %s" % (orig_stmt, stmt))
                pass
        

    # Check that there are subjects in the arguments if required
    # Return the list of subjects for later authorization
    def validate_arguments(self, client_cert, method, credentials, \
                               options, arguments, session):

        # Compute subjects
        subjects = self._compute_subjects(options, arguments, session)
#        chapi_info("SIC",  "Subjects = %s" % subjects)

        if subjects:
            if len(subjects) > 1:
                raise CHAPIv1ArgumentException("Can't have more " + \
                                                   "than one subject type")
            subject_type = subjects.keys()[0]
            subjects_of_type = subjects[subject_type]
            ensure_valid_urns(subject_type, subjects_of_type, session)

        return subjects

    # If there are subjects
    #    For each subject prove AUTHORITY.MAY_$method(SUBJECT)<-CALLER
    # If there are no subjects (and this is allowed by validate_arguments)
    #    Prove AUTHORITYMAY_$method<-CALLER
    def authorize_call(self, client_cert, method, credentials, options, \
                           arguments, subjects, session):
        abac_manager =  ABACManager(certs_by_name = {"CALLER" : client_cert}, 
                                    cert_files_by_name = {"ME" : self.cert_file}, 
                                    key_files_by_name = {"ME" : self.key_file},
                                    manage_context = False)
        abac_manager._verbose = True

        client_urn = get_urn_from_cert(client_cert)

        # Generate context-free assertions for caller
        if lookup_operator_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_OPERATOR<-CALLER")
        if lookup_pi_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_PI<-CALLER")
        if lookup_authority_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_AUTHORITY<-CALLER")
        abac_manager.register_assertion("ME.IS_%s<-CALLER" % flatten_urn(client_urn))

        # if there are subjects:
        # For each subject
        # Bind context assertions (BELONGS_TO <+ Each role)
        #   Bind required variables for all assertions (optional) 
        #      and policies (required)
        #   Compute and assert assertions for which all variables are bound
        #   Compute and assert policies (error if any not bound)
        #   try to prove EITHER:
        #      ME.MAY_$METHOD<-CALLER
        #   or ME.MAY_$METHOD_$SUBJECT<-CALLER
        # Give exception on any failure, success if all pass
        if subjects and len(subjects) > 0:
            subject_type = subjects.keys()[0]
            subjects_of_type = subjects[subject_type]
            for subject in subjects_of_type:

                self._generate_bindings(client_urn, subject_type, \
                                            subject, options, arguments, \
                                            session)
                self._assert_bound_statements(abac_manager, self._assertions)
                self._assert_bound_statements(abac_manager, self._policies)

                queries = [
                    "ME.MAY_%s_%s<-CALLER" % (method.upper(), \
                                                  flatten_urn(subject)), 
                    "ME.MAY_%s<-CALLER" % method.upper()
                    ]
                one_succeeded = False
                for query in queries:
                    ok, proof = abac_manager.query(query)
                    if abac_manager._verbose:
                        chapi_audit_and_log("ABAC", 
                                            "Testing ABAC query %s OK = %s" % \
                                                (query, ok), logging.DEBUG)
                    if ok:
                        one_succeeded = True
                        break
                if not one_succeeded:
                    template = "Caller not authorized to call method %s " + \
                        "with options %s arguments %s queries %s"
                    raise CHAPIv1AuthorizationError(template % \
                            (method, options, arguments, queries));

        else:
            self._assert_bound_statements(abac_manager, self._assertions)
            self._assert_bound_statements(abac_manager, self._policies)
            query ="ME.MAY_%s<-CALLER" % method.upper()
            ok, proof = abac_manager.query(query)
            if abac_manager._verbose:
                chapi_audit_and_log("ABAC", "Testing ABAC query %s OK = %s" % \
                                        (query, ok), logging.DEBUG)
            if not ok:
                template = "Caller not authorized to call method %s " + \
                    "with options %s arguments %s query %s"
                raise CHAPIv1AuthorizationError(template % \
                                                    (method, options, \
                                                         arguments, query));


class RowCheck(object):
    def permit(self, client_cert, credentials, urn):
        raise CHAPIv1NotImplementedError("Abstract Base class: RowCheck")

# # An ABAC check gathers a set of assertions and then validates a set of queries
# # If all queries pass, then the overall Check passes
# An ABAC Guard Base maintains a list of invocation checks and row checks
# Before we can invoke a method, make sure that all the invocation checks pass
# Then after we have results, make sure all the row checks check for each row (discarding rows that fail)
class ABACGuardBase(GuardBase):
    def __init__(self):
        GuardBase.__init__(self)
        self.db = pm.getService('chdbengine')
        #mapper(MemberAttribute, self.db.MEMBER_ATTRIBUTE_TABLE)

    # Base class: Provide a list of argument checks, 
    # invocation_checks and row_checks
    def get_argument_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_argument_check')
    def get_invocation_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_invocation_check')
    def get_row_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_row_check')


    def validate_call(self, client_cert, method, credentials, options, 
                      arguments, session):
#        print "ABACGuardBase.validate_call : " + method + " " + str(arguments) + " " + str(options)

        self.user_check(client_cert, session)

        argument_check = self.get_argument_check(method)
        if argument_check:
            argument_check.validate(options, arguments)
        
        invocation_check = self.get_invocation_check(method)
        if invocation_check:
            invocation_check.validate(client_cert, method, 
                                      credentials, options, arguments,
                                      session)

    def user_check(self, client_cert, session):
        client_urn = get_urn_from_cert(client_cert)
        client_uuid = get_uuid_from_cert(client_cert)
        client_name = get_name_from_urn(client_urn)

        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == client_uuid).\
            filter(MemberAttribute.name == MA_constants.field_mapping['_GENI_MEMBER_ENABLED'])
        rows = q.all()
        is_enabled = (len(rows)==0 or rows[0][0] == 'y')

        if is_enabled:
            #chapi_debug("ABAC", "UC: user '%s' (%s) enabled" % (client_name, client_urn))
            pass
        else:
            chapi_audit_and_log("ABAC", "UC: user '%s' (%s) disabled" % (client_name, client_urn))
            raise CHAPIv1AuthorizationError("User %s (%s) disabled" % (client_name, client_urn));

    # Support speaks-for invocation:
    # If a speaks-for credential is provided and 
    # a matching 'speaking_for' option is provided
    # If so, return the cert of the agent who signed the speaks-for
    #   credential and put the original (invoking) client_cert in a 
    #   'speaking_as' option
    def adjust_client_identity(self, client_cert, credentials, options, 
                               trusted_roots):
        return determine_speaks_for(client_cert, credentials, options,
                                    trusted_roots)

    def protect_results(self, client_cert, method, credentials, results):
        return results


# Method to convert
# dictionary of method => arguments for creating SubjectInvocationChecks 
#into a dictionary method => SubjectInvocationCheck
def create_subject_invocation_checks_orig(policies):
    checks = {}
    for method, args in policies.items():
        policies = args['policies']
        asserters = args['asserters']
        extractor = args['extractor']
        pass_empty_subject = args['pass_empty_subject']
        checks[method] = \
            SubjectInvocationCheckOrig(policies, asserters, \
                                           extractor, pass_empty_subject)
    return checks

# Method to convert
# dictionary of method => arguments for creating SubjectInvocationChecks 
#into a dictionary method => SubjectInvocationCheck
def create_subject_invocation_checks(policies):
    checks = {}
    for method, args in policies.items():
        policies = args['policies']
        assertions = args['assertions']
        pass_empty_subject = args['pass_empty_subject']
        checks[method] = \
            SubjectInvocationCheck(policies, assertions, pass_empty_subject)
    return checks
