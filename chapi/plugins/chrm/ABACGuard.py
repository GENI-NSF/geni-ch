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

from CHDatabaseEngine import CHDatabaseEngine
import amsoil.core.pluginmanager as pm
from  sqlalchemy import *
from  sqlalchemy.orm import aliased
from cert_utils import *
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
import types
from ABAC import *
from SpeaksFor import determine_speaks_for
from tools.ABACManager import ABACManager
from ArgumentCheck import *
from chapi.Memoize import memoize
import threading
from geni_constants import *
from geni_utils import *

# context support
_context = threading.local()

def cache_get(k):
    if not hasattr(_context, 'cache'):
        _context.cache = dict()
    if k not in _context.cache:
        _context.cache[k] = dict()
    return _context.cache[k]

def cache_clear():
    if hasattr(_context, 'cache'):
        del _context.cache

# Some helper methods

@memoize
def extract_user_urn(client_cert):
    client_cert_object = \
        sfa.trust.certificate.Certificate(string=client_cert)
    user_urn = None
    identifiers = client_cert_object.get_extension('subjectAltName')
    identifier_parts = identifiers.split(',')
    for identifier in identifier_parts:
        identifier = identifier.strip()
        if identifier.startswith('URI:urn:publicid'):
            user_urn = identifier[4:]
            break
    return user_urn

@memoize
def lookup_project_name_for_slice(slice_urn):
    parts = slice_urn.split("+")
    authority = parts[1]
    authority_parts = authority.split(":")
    project_name = authority_parts[1]
    return project_name


# Return a string based on a URN but with all punctuation (+:-.) replaced with _
def flatten_urn(urn):
    return urn.replace(':', '_').replace('+', '_').replace('-', '_').replace('.', '_')

def lookup_project_names_for_user(user_urn):
    cache = cache_get('project_names_for_user')
    if user_urn in cache:
        return cache[user_urn]

    db = pm.getService('chdbengine')
    session = db.getSession()

    q = session.query(db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE, db.PROJECT_MEMBER_TABLE)
    q = q.filter(db.PROJECT_TABLE.c.expired == 'f')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    session.close()
    
    project_names = [row.project_name for row in rows]
    cache[user_urn] = project_names
    return project_names

def convert_slice_uid_to_urn(slice_uid):
    cache = cache_get('slice_uid_to_urn')
    if slice_uid in cache:
        return cache[slice_uid]

    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(db.SLICE_TABLE.c.slice_urn)
    q = q.filter(db.SLICE_TABLE.c.slice_id == slice_uid)
    rows = q.all()
    session.close()
    slice_urn = rows[0].slice_urn
    cache[slice_uid] = slice_urn
    return slice_urn

def convert_project_uid_to_urn(project_uid):
    cache = cache_get('project_uid_to_urn')
    if project_uid in cache:
        return cache[project_uid]

    config = pm.getService('config')
    authority = config.get("chrm.authority")
    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(db.PROJECT_TABLE.c.project_name)
    q = q.filter(db.PROJECT_TABLE.c.project_id == project_uid)
    rows = q.all()
    session.close()
    project_name = rows[0].project_name
    project_urn = to_project_urn(authority, project_name)
    cache[project_uid] = project_urn
    return project_urn

def convert_member_uid_to_urn(member_uid):
    cache = cache_get('member_uid_to_urn')
    if member_uid in cache:
        return cache[member_uid]
    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == member_uid)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    rows = q.all()
    session.close()
    member_urn = rows[0].value
    cache[member_uid] = member_urn
    return member_urn


def lookup_operator_privilege(user_urn):
    cache = cache_get('operator_privilege')
    if user_urn in cache:
        return cache[user_urn]
    db = pm.getService('chdbengine')
    session = db.getSession()

    OPERATOR_ATTRIBUTE = 5
    SLICE_CONTEXT = 2

    q = session.query(db.CS_ASSERTION_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.context_type == SLICE_CONTEXT)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.CS_ASSERTION_TABLE.c.principal)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    session.close()
    cache[user_urn] = (len(rows)>0)
    return len(rows) > 0

def lookup_pi_privilege(user_urn):
    cache = cache_get('pi_privilege')
    if user_urn in cache:
        return cache[user_urn]
    db = pm.getService('chdbengine')
    session = db.getSession()

    OPERATOR_ATTRIBUTE = 5
    RESOURCE_CONTEXT = 3

    q = session.query(db.CS_ASSERTION_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.context_type == RESOURCE_CONTEXT)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.CS_ASSERTION_TABLE.c.principal)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    session.close()
    cache[user_urn] = (len(rows)>0)
    return len(rows) > 0

# Methods to generate assertions based on relationship between the CALLER 
# and the SUBJECT

# If given caller and given subject share a common project
# Generate an ME.SHARES_PROJECT_$subject<-caller assertion
def assert_shares_project(caller_urn, member_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()

    pm1 = aliased(db.PROJECT_MEMBER_TABLE)
    pm2 = aliased(db.PROJECT_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(pm1.c.project_id, pm2.c.project_id, ma1.c.value, ma2.c.value)
    q = q.filter(pm1.c.project_id == pm2.c.project_id)
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(pm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value == member_urn)

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)
    session.close()
    if len(rows) > 0:
        assertion = "ME.SHARES_PROJECT_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

# If given caller and given subject share a common slice
# Generate an ME.SHARES_SLICE(subject)<-caller assertion
def assert_shares_slice(caller_urn, member_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()

    sm1 = aliased(db.SLICE_MEMBER_TABLE)
    sm2 = aliased(db.SLICE_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(sm1.c.slice_id, sm2.c.slice_id, ma1.c.value, ma2.c.value)
    q = q.filter(sm1.c.slice_id == sm2.c.slice_id)
    q = q.filter(sm1.c.member_id == ma1.c.member_id)
    q = q.filter(sm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value == member_urn)

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)
    session.close()

    if len(rows) > 0:
        assertion = "ME.SHARES_SLICE_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

# Assert ME.IS_$ROLE(SLICE)<-CALLER for the roles caller has on slice
def assert_slice_role(caller_urn, slice_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()

    q = session.query(db.SLICE_MEMBER_TABLE.c.role, db.SLICE_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.SLICE_MEMBER_TABLE.c.slice_id == db.SLICE_TABLE.c.slice_id)
    q = q.filter(db.SLICE_TABLE.c.slice_urn == slice_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.SLICE_MEMBER_TABLE.c.member_id)
    rows = q.all()
    session.close()
    
    for row in rows:
        role = row.role
        role_name = attribute_type_names[role]
        assertion = "ME.IS_%s_%s<-CALLER" % (role_name, flatten_urn(slice_urn))
        abac_manager.register_assertion(assertion)

# Assert ME.IS_$ROLE_$PROJECT<-CALLER for the roles caller has on project
def assert_project_role(caller_ur, project_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()
    project_name = get_name_from_urn(project_urn)

    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name == project_name)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()
    session.close()
    
    for row in rows:
        role = row.role
        role_name = attribute_type_names[role]
        assertion = "ME.IS_%s_%s<-CALLER" % (role_name, flatten_urn(project_urn))
        abac_manager.register_assertion(assertion)


# Assert ME.BELONGS_TO_$SLICE<-CALLER if caller is member of slice
def assert_belongs_to_slice(caller_urn, slice_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()

    q = session.query(db.SLICE_MEMBER_TABLE.c.role, db.SLICE_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.SLICE_MEMBER_TABLE.c.slice_id == db.SLICE_TABLE.c.slice_id)
    q = q.filter(db.SLICE_TABLE.c.slice_urn == slice_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.SLICE_MEMBER_TABLE.c.member_id)
    rows = q.all()
    session.close()

    if len(rows) > 0:
        assertion = "ME.BELONGS_TO_%s<-CALLER" % flatten_urn(slice_urn)
        abac_manager.register_assertion(assertion)


# Assert ME.BELONGS_TO_$PROJECT<-CALLER if caller is member of project
def assert_belongs_to_project(caller_urn, project_urn, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()
    project_name = get_name_from_urn(project_urn)

    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name == project_name)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()
    session.close()

    if len(rows) > 0:
        assertion = "ME.BELONGS_TO_%s<-CALLER" % flatten_urn(project_urn)
        abac_manager.register_assertion(assertion)


# Extractors to extract subject identifiers from request
# These return a dictionary of {'SUBJECT_TYPE : [List of SUBJECT IDENTIFIERS OF THIS TYPE]}

# Default subject extractor, only take from the options, ignore arguments
def standard_subject_extractor(options, arguments):
    extracted = {}
    if 'match' not in options:
        raise CHAPIv1ArgumentError("No match option for query")
    match_option = options['match']
    if "SLICE_URN" in match_option:
        extracted["SLICE_URN"] =  match_option['SLICE_URN']
    if "SLICE_UID" in match_option:
        slice_uids = match_option['SLICE_UID']
        if not isinstance(slice_uids, list): slice_uids = [slice_uids]
        slice_urns = [convert_slice_uid_to_urn(slice_uid) for slice_uid in slice_uids]
        extracted["SLICE_URN"] = slice_urns
    if "PROJECT_URN" in match_option:
        extracted["PROJECT_URN"] =  match_option['PROJECT_URN']
    if "PROJECT_UID" in match_option:
        project_uids = match_option['PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = [convert_project_uid_to_urn(project_uid) for project_uid in project_uids]
        extracted["PROJECT_URN"] = project_urns
    if "_GENI_PROJECT_UID" in match_option:
        project_uids = match_option['_GENI_PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = [convert_project_uid_to_urn(project_uid) for project_uid in project_uids]
        extracted["PROJECT_URN"] = project_urns
    if "MEMBER_URN" in match_option:
        extracted["MEMBER_URN"] =  match_option['MEMBER_URN']
    if "MEMBER_UID" in match_option:
        member_uids = match_option['MEMBER_UID']
        if not isinstance(member_uids, list): member_uids = [member_uids]
        member_urns = [convert_member_uid_to_urn(member_uid) for member_uid in member_uids]
        extracted["MEMBER_URN"] = member_urns
    return extracted

def key_subject_extractor(options, arguments):
    extracted = {}
    if 'match' not in options:
        raise CHAPIv1ArgumentError("No match option for query")
    match_option = options['match']
    if 'KEY_MEMBER' in match_option:
        extracted['MEMBER_URN'] = match_option['KEY_MEMBER']
    return extracted
        

def project_urn_extractor(options, arguments):
    project_urn = arguments['project_urn']
    return {"PROJECT_URN" : [project_urn]}

def slice_urn_extractor(options, arguments):
    slice_urn = arguments['slice_urn']
    return {"SLICE_URN" : [slice_urn]}

def member_urn_extractor(options, arguments):
    member_urn = arguments['member_urn']
    return {"MEMBER_URN" : [member_urn]}


# class ABACAssertionGenerator(object): 
#     def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
#         raise CHAPIv1NotImplementedError("Absract Base class: ABACAssertionGenerator")

# class OperatorAsserter(ABACAssertionGenerator):
#     def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
#         user_urn = extract_user_urn(client_cert)
#         is_operator = lookup_operator_privilege(user_urn)
#         if is_operator:
#             abac_manager.register_assertion("ME.is_operator<-C")

# class ProjectMemberAsserterByURN(ABACAssertionGenerator):
#     def generate_assertions(self, abac_manager, client_cert, credentials, arguments, user_urn):
#         user_project_names = lookup_project_names_for_user(user_urn)
#         for user_project_name in user_project_names:
#             assertion = "ME.is_member_%s<-C" % str(user_project_name)
#             abac_manager.register_assertion(assertion)

# class ProjectMemberAsserterByCert(ProjectMemberAsserterByURN):
#     def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
#         user_urn = extract_user_urn(client_cert)
#         super(self.__class__, self).generate_assertions(abac_manager, \
#                                                             client_cert, credentials, arguments, user_urn)

# class ABACQueryGenerator(object): 
#     def generate_query(self, client_cert, credentials, arguments, urn):
#         raise CHAPIv1NotImplementedError("Absract Base class: ABACQueryGenerator")

# # Is client (C) a member of the project associated with the given slice URN?
# class QueryProjectMember(ABACQueryGenerator):
#     def generate_query(self, client_cert, credentials, arguments, user_urn):
#         urn_project_names = lookup_project_names_for_user(user_urn)
#         return [["C", "is_member_%s" % str(urn_project_name)]  for urn_project_name in urn_project_names]

# # Is client (C) a member of the project associated
# class QueryProjectMemberBySliceURN(ABACQueryGenerator):
#     def generate_query(self, client_cert, credentials, arguments, slice_urn):
#         urn_project_name = lookup_project_name_for_slice(slice_urn)
#         return [["C", "is_member_%s" %  str(urn_project_name)]]

# Pre-processor for method invocations
class InvocationCheck(object):

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    def validate_arguments(self, method, options, arguments):
        # Method-specific logic
        pass

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/argumentspassed to the call
    def authorize_call(self, client_cert, method, credentials, options, arguments):
        raise CHAPIv1NotImplementedError("Abstract Base class: InvocationCheck")

    # Validate arguments and check authorization
    def validate(self, client_cert, method, credentials, options, arguments):
        self.validate_arguments(method, options, arguments)
        self.authorize_call(client_cert, method, credentials, options, arguments)

# Class that determines if the caller has the right to invoke a given method on all
# the subjects of a given method invocation
class SubjectInvocationCheck(InvocationCheck):

    def __init__(self, policies, attribute_extractor, subject_extractor):
        self._policies = policies
        self._attribute_extractor = attribute_extractor
        self._subject_extractor = subject_extractor
        self._subjects = None
        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")

    # Check that there are subjects in the arguments if required
    # Store the list of subjects for later authorization
    def validate_arguments(self, method, options, arguments):
        if self._subject_extractor:
            self._subjects = self._subject_extractor(options, arguments)
            if not self._subjects or len(self._subjects) == 0:
                import pdb; pdb.set_trace()
                raise CHAPIv1ArgumentError("No subjects supplied to call %s" % method);
            if len(self._subjects) > 1:
                raise CHAPIv1ArgumentError("Can't provide mixture of subject types for call %s: %s" % \
                                               (method, self._subjects.keys()))

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
    def authorize_call(self, client_cert, method, credentials, options, arguments):
        abac_manager = \
            ABACManager(certs_by_name = {"CALLER" : client_cert}, 
                        cert_files_by_name = {"ME" : self.cert_file}, 
                        key_files_by_name = {"ME" : self.key_file});
#        abac_manager._verbose = True

        client_urn = get_urn_from_cert(client_cert)

        # Gather assertions for caller
        if lookup_operator_privilege(client_urn):
            abac_manager.register_assertion("ME.IS_OPERATOR<-CALLER")
        if lookup_pi_privilege(client_urn):
            abac_manager.register_assertion("ME.IS_PI<-CALLER")
        abac_manager.register_assertion("ME.IS_%s<-CALLER" % flatten_urn(client_urn))

        if self._subjects:
            for subject_type in self._subjects.keys():
                subjects_of_type = self._subjects[subject_type]
                if not isinstance(subjects_of_type, list) : subjects_of_type = [subjects_of_type]
                for subject in subjects_of_type:
#                    print "SUBJECT = " + subject
                    subject_name = flatten_urn(subject)

                    self.load_policies(abac_manager, subject_name)

                    if self._attribute_extractor:
                        # Try to make an assertion about the relationship between the caller and subject
                        # And store assertion in abac_manager
                        self._attribute_extractor(client_urn, subject, abac_manager)

                    queries = [
                        "ME.MAY_%s_%s<-CALLER" % (method.upper(), subject_name), 
                        "ME.MAY_%s<-CALLER" % method.upper()
                        ]

                    one_succeeded = False
                    for query in queries:
                        ok, proof = abac_manager.query(query)
#                        print "Q = " + query + " OK = " + str(ok)
                        if ok:
                            one_succeeded = True
                            break

                    if not one_succeeded:
                        raise CHAPIv1AuthorizationError(\
                            "Caller not authorized to call method %s with options %s arguments %s queries %s" %\
                                (method, options, arguments, queries));
                    
        else:
            self.load_policies(abac_manager, None)

            query ="ME.MAY_%s<-CALLER" % method.upper()
            ok, proof = abac_manager.query(query)
            if not ok:
                raise CHAPIv1AuthorizationError(\
                    "Caller not authorized to call method %s with options %s arguments %s query %s" %\
                        (method, options, arguments, query));


class RowCheck(object):
    def permit(self, client_cert, credentials, urn):
        raise CHAPIv1NotImplementedError("Abstract Base class: RowCheck")
        

# # An ABAC check gathers a set of assertions and then validates a set of queries
# # If all queries pass, then the overall Check passes
# class ABACCheck(object):

#     def __init__(self, asserters, queries):
#         self._asserters = asserters
#         self._queries = queries
#         self.config = pm.getService('config')
#         self.key_file = self.config.get("chapiv1rpc.ch_key")
#         self.cert_file = self.config.get("chapiv1rpc.ch_cert")

#     def compute(self, client_cert, credentials, arguments, urn):

#         # Bind entities : C = client_cert, ME = auth_cert, auth_key
#         certs_by_name = {'C' : client_cert, 'ME' : self.cert_file}
#         abac_manager = \
#             ABACManager(certs_by_name = {"C" : client_cert}, \
#                             cert_files_by_name = {"ME" : self.cert_file}, \
#                             key_files_by_name = {"ME" : self.key_file})

#         # Gather all assertions about context
#         for asserter in self._asserters:
#             asserter.generate_assertions(abac_manager, client_cert, credentials, arguments, urn)

#         # Compute queries from ABAC: If any pass, we permit.
#         for query in self._queries:
#             if isinstance(query, ABACQueryGenerator):
#                 # A query generate can return a list of queries, any one of which is sufficient to accept
#                 target_roles = query.generate_query(client_cert, credentials, arguments, urn)
#             else:
#                 target_roles = [query]

#             for target_role in target_roles:
#                 q_target = target_role[0]
#                 q_role = target_role[1]
#                 query_expression = "ME.%s<-%s" % (q_role, q_target)

#                 ok, proof = abac_manager.query(query_expression)
#                 if ok:
# #                    print "Proof " + "\n".join(abac_manager.pretty_print_proof(proof))
#                     return True
#         return False

# # For testing whether a method invocation is permitted
# class ABACInvocationCheck(ABACCheck, InvocationCheck):

#     def __init__(self, asserters, queries):
#         ABACCheck.__init__(self, asserters, queries)

#     def authorize_call(self, client_cert, method, credentials, arguments):
#         urn = None
#         if arguments.has_key('slice_urn'):
#             urn = arguments['slice_urn']
#         elif arguments.has_key('user_urn'):
#             urn = arguments['user_urn']
#         if not self.compute(client_cert, credentials, arguments, urn):
#             raise CHAPIv1AuthorizationError("Call not authorized: " + method)

# # For testing whether a given data row is permitted to be exposed to caller
# class ABACRowCheck(ABACCheck, RowCheck):
#     def __init__(self, asserters, queries): 
#         ABACCheck.__init__(self, asserters, queries)

#     def permit(self, client_cert, credentials, urn):
#         return self.compute(client_cert, credentials, {}, urn)

# An ABAC Guard Base maintains a list of invocation checks and row checks
# Before we can invoke a method, make sure that all the invocation checks pass
# Then after we have results, make sure all the row checks check for each row (discarding rows that fail)
class ABACGuardBase(GuardBase):
    def __init__(self):
        GuardBase.__init__(self)

    # Base class: Provide a list of argument checks, 
    # invocation_checks and row_checks
    def get_argument_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_argument_check')
    def get_invocation_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_invocation_check')
    def get_row_check(self, method): 
        raise CHAPIv1NotImplementedError('Abstract Base class ABACGuard.get_row_check')


    def validate_call(self, client_cert, method, credentials, options, arguments = {}):
#        print "ABACGuardBase.validate_call : " + method + " " + str(arguments) + " " + str(options)


        argument_check = self.get_argument_check(method)
        if argument_check:
            argument_check.validate(options, arguments)
        
        invocation_check = self.get_invocation_check(method)
        if invocation_check:
            invocation_check.validate(client_cert, method, \
                                          credentials, options, arguments)

    # Support speaks-for invocation:
    # If a speaks-for credential is provided and 
    # a matching 'speaking_for' option is provided
    # If so, return the cert of the agent who signed the speaks-for
    #   credential and put the original (invoking) client_cert in a 
    #   'speaking_as' option
    def adjust_client_identity(self, client_cert, credentials, options):
        return determine_speaks_for(client_cert, credentials, options)

    def protect_results(self, client_cert, method, credentials, results):
        return results

