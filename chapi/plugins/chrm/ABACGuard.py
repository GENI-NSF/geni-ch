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
import time

logger = amsoil.core.log.getLogger('ABAC')


# Pre-processor for method invocations
class InvocationCheck(object):

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    # Return dictionary of {subject_type : subjects}
    def validate_arguments(self, client_cert, method, credentials,
                           options, arguments, session):
        # Method-specific logic
        return None

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/arguments passed to the call
    # and subjects extracted from validate_arguments call
    def authorize_call(self, client_cert, method, credentials, options,
                       arguments, subjects, session ):
        raise CHAPIv1NotImplementedError("Abstract Base class: InvocationCheck")

    # Validate arguments and check authorization
    def validate(self, client_cert, method, credentials, options, 
                 arguments, session):
        subjects = self.validate_arguments(client_cert, method, credentials,
                                           options, arguments, session)
        # de-duplicate the lists of subjects to minimize labor
        for key in subjects.keys():
            subjects[key] = list(set(subjects[key]))
        self.authorize_call(client_cert, method, credentials,
                            options, arguments, subjects, session)

# Class that determines if the caller has the right to invoke a given method on all
# the subjects of a given method invocation
class SubjectInvocationCheck(InvocationCheck):

    def __init__(self, policies, assertions):
        self._policies = policies
        if not policies: self._policies = []
        if policies and not isinstance(policies, list):
            self._policies = [policies]

        self._assertions = assertions
        if not assertions: self._assertions = []
        if assertions and not isinstance(assertions, list):
            self._assertions = [assertions]

        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")
        self._bindings = {}

    # All recognized binding types (variables that can be
    # substituted in assertions and policies)
    RECOGNIZED_BINDINGS = ["$ROLE", "$SLICE", "$PROJECT", \
                               "$MEMBER", "$SELF", \
                               "$SHARES_SLICE", "$SHARES_PROJECT", \
                               "$PROJECT_LEAD", "$PROJECT_ADMIN", \
                               "$SEARCHING_BY_EMAIL", \
                               "$SEARCHING_FOR_PROJECT_LEAD_BY_UID", \
                               "$PENDING_REQUEST_TO_MEMBER", \
                               "$PENDING_REQUEST_FROM_MEMBER", \
                               "$REQUEST_ID", \
                               "$REQUEST_ROLE", \
                               "$REQUESTOR", \
                               "$KEY_OWNER"]

    def _gather_bindings(self, template):
        for recognized_binding in SubjectInvocationCheck.RECOGNIZED_BINDINGS:
            if template.find(recognized_binding) > 0:
                if recognized_binding not in self._bindings:
                    self._bindings[recognized_binding] = None

    def _compute_subjects(self, options, arguments, session):
        subjects = {}
        urns, label = self._compute_slice_subjects(options, arguments, session)

        if urns is not None:
            subjects[label] = urns
        urns, label = self._compute_project_subjects(options, arguments, session)
        if urns is not None:
            subjects[label] = urns

        urns, label = self._compute_member_subjects(options, arguments, session)
        if urns is not None:
            subjects[label] = urns

        urns, label = self._compute_request_subjects(options, arguments, session)
        if urns is not None:
            subjects[label] = urns

        urns, label = self._compute_key_subjects(options, arguments, session)
        if urns is not None:
            subjects[label] = urns

        urns, label = self._compute_sliver_subjects(options, arguments, session)
        if urns is not None:
            subjects[label] = urns

            
        for label, urns in subjects.items():
            if not isinstance(urns, list): subjects[label] = [urns]
#        chapi_info("_compute_subjects", "SUBJECTS = %s" % subjects)
        return subjects

    def _compute_slice_subjects(self, options, arguments, session):
        urns = None
        db = pm.getService('chdbengine')
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
        elif 'attributes' in arguments:
            attributes = arguments['attributes']
            if 'SLICE' in attributes:
                slice_uid = attributes['SLICE']
                urns = convert_slice_uid_to_urn(slice_uid, session)

#        chapi_info("C_S_S", "%s" % urns)

        return urns, "SLICE_URN"

    def _compute_project_subjects(self, options, arguments, session):
        urns = None
        db = pm.getService('chdbengine')
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
        elif 'attributes' in arguments:
            attributes = arguments['attributes']
            if 'PROJECT' in attributes:
                project_uid = attributes['PROJECT']
                urns = convert_project_uid_to_urn(project_uid, session)

#        chapi_info("C_P_S", "%s" % urns)

        return urns, "PROJECT_URN"

    def _compute_member_subjects(self, options, arguments, session):
        urns = None
        db = pm.getService('chdbengine')
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

        if urns is None:
            if 'fields' in options and 'KEY_MEMBER' in options['fields']:
                urns = options['fields']['KEY_MEMBER']
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
                    raise CHAPIv1ArgumentError("No key with given ID %s"\
                                                   % key_id)
                member_id = rows[0].member_id
                urns = convert_member_uid_to_urn(member_id, session)
            elif 'principal' in arguments:
                principal_uid = arguments['principal']
                urns = convert_member_uid_to_urn(principal_uid, session)
            elif 'user_id' in arguments:
                user_uid = arguments['user_id']
                urns = convert_member_uid_to_urn(user_uid, session)
            elif 'context_type' in arguments and 'context_id' in arguments \
                    and arguments['context_type'] == MEMBER_CONTEXT:
                member_uid = arguments['context_id']
                urns = convert_member_uid_to_urn(member_uid, session)
            elif 'attributes' in arguments:
                attributes = arguments['attributes']
                if 'MEMBER' in attributes:
                    member_uid = attributes['MEMBER']
                    urns = convert_member_uid_to_urn(member_uid, session)

#        chapi_info("C_M_S", "%s" % urns)

        return urns, "MEMBER_URN"

    # Grab sliver URNs from arguments
    def _compute_sliver_subjects(self, options, arguments, session):
        if 'sliver_urn' in arguments:
            return arguments['sliver_urn'], 'SLIVER_URN'
        return None, None

    # Grab request ID's from arguments
    def _compute_request_subjects(self, options, arguments, session):
        if 'request_id' in arguments:
            request_id = arguments['request_id']
            return request_id, 'REQUEST_ID'
        return None, None

    # Grab request key's from arguments
    def _compute_key_subjects(self, options, arguments, session):
        key_id = None
        if 'match' in options and 'KEY_ID' in options['match']:
            key_id = options['match']['KEY_ID']
        elif 'key_id' in arguments:
            key_id = arguments['key_id']
        return key_id, 'KEY_ID'

    # Generate groups of assertions into a single label
    # e.g. BELONGS_TO means IS_LEAD, IS_ADMIN, ....
    def _generate_assertion_groups(self, subject_type, subject, abac_manager):
        if subject_type in ['SLICE_URN', 'PROJECT_URN']:
            for role, role_name in attribute_type_names.items():
                assertion = "ME.BELONGS_TO_%s<-ME.IS_%s_%s" % \
                    (flatten_urn(subject), role_name, flatten_urn(subject))
                abac_manager.register_assertion(assertion)

    def _generate_bindings_for_subjects(self, caller_urn, subject_type, subjects, \
                               options, arguments, session):

        authority = pm.getService('config').get("chrm.authority")

#        chapi_info('gen_bindings', "Subject Type: %s; self.bindings: %s; subjects: %s" % (subject_type, self._bindings, subjects))

        # Prepare a set of bindings (label => value) for each subject
        bindings_by_subject = {}
        for subject in subjects: 
            bindings_by_subject[subject] = {}

#        chapi_info("ABAC", "BINDINGS = %s" % self._bindings)

        for binding in self._bindings:
            if binding == "$ROLE":
                if subject_type == "SLICE_URN":
                    rows = get_slice_role_for_member(caller_urn, \
                                                         subjects, session)
                    for row in rows:
                        role = row.role
                        role_name = attribute_type_names[role]
                        subject = row.slice_urn
                        bindings_by_subject[subject][binding] = role_name
                elif subject_type == "PROJECT_URN":
                    rows = get_project_role_for_member(caller_urn, \
                                                            subjects, session)
                    for row in rows:
                        role = row.role
                        role_name = attribute_type_names[role]
                        project_name = row.project_name
                        subject = to_project_urn(authority, project_name)
                        bindings_by_subject[subject][binding] = role_name
                else:
                    # Can't compute role for other than slice/project
                    continue

            elif binding == "$SLICE":
                if subject_type == "SLICE_URN":
                    for subject in subjects: 
                        bindings_by_subject[subject][binding]=subject
            elif binding == "$PROJECT":
                if subject_type == "PROJECT_URN":
                    for subject in subjects: 
                        bindings_by_subject[subject][binding]=subject
            elif binding == "$MEMBER":
                if subject_type == "MEMBER_URN":
                    for subject in subjects: 
                        bindings_by_subject[subject][binding]=subject
            elif binding == "$SELF":
                for subject in subjects:
                    bindings_by_subject[subject][binding]=caller_urn
            elif binding == "$SHARES_SLICE":
                if subject_type == "MEMBER_URN":
                    sharers = shares_slice(caller_urn, subjects, session)
                    for sharer in sharers:
                        bindings_by_subject[sharer][binding] = "SHARES_SLICE"
            elif binding == "$SHARES_PROJECT":
                if subject_type == "MEMBER_URN":
                    sharers = shares_project(caller_urn, subjects, session)
                    for sharer in sharers:
                        bindings_by_subject[sharer][binding] = "SHARES_PROJECT"
            elif binding == "$PROJECT_LEAD":
                # Fill in this binding if the _caller_ is a project lead on some project.
                # Use this EG so a project lead/admin can look up details of people they want to add to a project
                leads = has_role_on_some_project([caller_urn], LEAD_ATTRIBUTE,
                                                 session)
                if caller_urn in leads:
                    for subject in subjects:
                        bindings_by_subject[subject][binding] = "PROJECT_LEAD"
            elif binding == "$PROJECT_ADMIN":
                # Fill in this binding if the _caller_ is a project lead on some project.
                # Use this EG so a project lead/admin can look up details of people they want to add to a project
                admins = has_role_on_some_project([caller_urn], ADMIN_ATTRIBUTE,
                                                  session)
                if caller_urn in admins:
                    for subject in subjects:
                        bindings_by_subject[subject][binding] = "PROJECT_ADMIN"
            elif binding == "$SEARCHING_BY_EMAIL":
                # Is this a lookup by email address?
                # Specifically, project leads/admins should be allowed to look
                # up member info for members not in their project by email address,
                # to support adding members by email address
                if 'match' in options and 'MEMBER_EMAIL' in options['match']:
                    for subject in subjects:
                        bindings_by_subject[subject][binding] = "SEARCHING_BY_EMAIL"
            elif binding == "$SEARCHING_FOR_PROJECT_LEAD_BY_UID":
                if 'match' in options and 'MEMBER_UID' in options['match']:
                    leads = \
                        has_role_on_some_project(subjects, LEAD_ATTRIBUTE,\
                                                     session)
                    for lead in leads:
                        bindings_by_subject[lead][binding] = "SEARCHING_FOR_PROJECT_LEAD_BY_UID"
            elif binding == "$PENDING_REQUEST_TO_MEMBER":

                # This means I have a pending request to one of these people
                # Meaning the request is created by me
                # and is on a project of which they are lead or admin
                if subject_type == "MEMBER_URN":
                    leads = \
                        has_pending_request_on_project_lead_by(subjects, [caller_urn], 
                                                               True,
                                                               session)
                    for lead in leads:
                        bindings_by_subject[lead][binding] = "PENDING_REQUEST_TO_MEMBER"

            elif binding == "$PENDING_REQUEST_FROM_MEMBER":

                # This means I have a pending request from one of these people
                # Meaning the request is created by me
                # and is on a project of which they are lead or admin
                if subject_type == "MEMBER_URN":
                    requestors = \
                        has_pending_request_on_project_lead_by([caller_urn],  subjects, 
                                                               False,
                                                               session)
                    for requestor in requestors:
                        bindings_by_subject[requestor][binding] = "PENDING_REQUEST_FROM_MEMBER"


            elif binding == "$REQUEST_ID":
                if subject_type == "REQUEST_ID":
                    for subject in subjects:
                        bindings_by_subject[subject][binding] = subject
            elif binding == "$REQUEST_ROLE":
                if subject_type == "REQUEST_ID":
                    for subject in subjects:
                        project_urn = \
                            get_project_request_project_urn(subject, session)
                        if project_urn is not None:
                            rows = get_project_role_for_member(caller_urn, \
                                                                   project_urn, \
                                                                   session)
                            if len(rows) > 0:
                                role = rows[0].role
                                role_name = attribute_type_names[role]
                                bindings_by_subject[subject][binding] = role_name
            elif binding == "$REQUESTOR":
                if subject_type == "REQUEST_ID":
                    for subject in subjects:
                        requestor_urn = get_project_request_requestor_urn(subject, session) 
                        if caller_urn == requestor_urn:
                            bindings_by_subject[subject][binding] = "REQUESTOR"

            elif binding == "$KEY_OWNER":
                if subject_type == "KEY_ID":
                    for subject in subjects:
                        key_owner_urn = get_key_owner_urn(subject, session);
                        if caller_urn == key_owner_urn:
                            bindings_by_subject[subject][binding] = caller_urn

        return bindings_by_subject

    def _assert_bound_statements(self, abac_manager, statements, bindings):
        for stmt in statements:
            orig_stmt = stmt
            for binding_name, binding_value in bindings.items():
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
        chapi_info("SIC",  "Subjects = %s" % subjects)

        for subject_type, subjects_of_type in subjects.items():
            ensure_valid_urns(subject_type, subjects_of_type, session)

        return subjects

    # If there are subjects
    #    For each subject prove AUTHORITY.MAY_$method(SUBJECT)<-CALLER
    # If there are no subjects (and this is allowed by validate_arguments)
    #    Prove AUTHORITYMAY_$method<-CALLER
    def authorize_call(self, client_cert, method, credentials, options, \
                           arguments, subjects, session):

        self._bindings = {}
        # Gather all required bindings
        for assertion in self._assertions:
            self._gather_bindings(assertion)
        for policy in self._policies:
            self._gather_bindings(policy)


        abac_manager =  ABACManager(certs_by_name = {"CALLER" : client_cert}, 
                                    cert_files_by_name = {"ME" : self.cert_file}, 
                                    key_files_by_name = {"ME" : self.key_file},
                                    manage_context = False)
        #abac_manager._verbose = True

        client_urn = get_urn_from_cert(client_cert)

        # Generate context-free assertions for caller
        if lookup_operator_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_OPERATOR<-CALLER")
        if lookup_pi_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_PI<-CALLER")
        if lookup_authority_privilege(client_urn, session):
            abac_manager.register_assertion("ME.IS_AUTHORITY<-CALLER")
        abac_manager.register_assertion("ME.IS_%s<-CALLER" % flatten_urn(client_urn))

#        chapi_info("ABAC", "SUBJECTS = %s" % subjects)

        # if there are subjects:
        # For each subject
        #   Bind assertion groups  (BELONGS_TO <+ Each role)
        #   Bind required variables for all assertions (optional) 
        #      and policies (required)
        #   Compute and assert assertions for which all variables are bound
        #   Compute and assert policies (error if any not bound)
        #   try to prove EITHER:
        #      ME.MAY_$METHOD<-CALLER
        #   or ME.MAY_$METHOD_$SUBJECT<-CALLER
        # Give exception on any failure, success if all pass
        if subjects and len(subjects) > 0:
            for subject_type, subjects_of_type in subjects.items():
                subjects_bindings = \
                    self._generate_bindings_for_subjects(client_urn, subject_type, 
                                                         subjects_of_type, options, arguments,
                                                         session)
#                chapi_info("ABAC", "SUBJECT_BINDINGS = %s" % subjects_bindings)

                for subject in subjects_of_type:
                    self._generate_assertion_groups(subject_type, subject, \
                                                        abac_manager)
                    bindings = subjects_bindings[subject]
                    
                    self._assert_bound_statements(abac_manager,
                                                  self._assertions, bindings)
                    self._assert_bound_statements(abac_manager, self._policies,
                                                  bindings)

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
            subject_type = 'MEMBER_URN'
            subjects_of_type = [client_urn]
            subjects_bindings \
                = self._generate_bindings_for_subjects(client_urn,
                                                       subject_type,
                                                       subjects_of_type,
                                                       options,
                                                       arguments,
                                                       session)
            bindings = subjects_bindings[client_urn]
            self._assert_bound_statements(abac_manager, self._assertions,
                                          bindings)
            self._assert_bound_statements(abac_manager, self._policies,
                                          bindings)
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
def create_subject_invocation_checks(check_specs):
    checks = {}
    for method, args in check_specs.items():
        policies = args['policies']
        assertions = args['assertions']
        checks[method] = SubjectInvocationCheck(policies, assertions)
    return checks
