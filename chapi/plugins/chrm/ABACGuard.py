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
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
import types
from ABAC import *
from tools.ABACManager import ABACManager
from ArgumentCheck import *

# Some helper methods

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

def lookup_project_name_for_slice(slice_urn):
    if not slice_urn: 
        import pdb; pdb.set_trace()
    parts = slice_urn.split("+")
    authority = parts[1]
    authority_parts = authority.split(":")
    project_name = authority_parts[1]
    return project_name

def lookup_project_names_for_user(user_urn):
    db = pm.getService('chdbengine')
    session = db.getSession()

    q = session.query(db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE, db.PROJECT_MEMBER_TABLE)
    q = q.filter(db.PROJECT_TABLE.c.expired == 'f')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    
    project_names = [row.project_name for row in rows]
    return project_names

def lookup_operator_privilege(user_urn):
    db = pm.getService('chdbengine')
    session = db.getSession()

    OPERATOR_ATTRIBUTE = 5
    SLICE_CONTEXT = 2

    q = session.query(db.ASSERTION_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(db.ASSERTION_TABLE.c.context_type == SLICE_CONTEXT)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.ASSERTION_TABLE.c.principal)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    return len(rows) > 0

class ABACAssertionGenerator(object): 
    def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
        raise CHAPIv1NotImplementedError("Absract Base class: ABACAssertionGenerator")

class OperatorAsserter(ABACAssertionGenerator):
    def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
        user_urn = extract_user_urn(client_cert)
        is_operator = lookup_operator_privilege(user_urn)
        if is_operator:
            abac_manager.register_assertion("ME.is_operator<-C")

class ProjectMemberAsserterByURN(ABACAssertionGenerator):
    def generate_assertions(self, abac_manager, client_cert, credentials, arguments, user_urn):
        user_project_names = lookup_project_names_for_user(user_urn)
        for user_project_name in user_project_names:
            assertion = "ME.is_member_%s<-C" % str(user_project_name)
            print "Asserting " + assertion
            abac_manager.register_assertion(assertion)

class ProjectMemberAsserterByCert(ProjectMemberAsserterByURN):
    def generate_assertions(self, abac_manager, client_cert, credentials, arguments, urn):
        user_urn = extract_user_urn(client_cert)
        super(self.__class__, self).generate_assertions(abac_manager, \
                                                            client_cert, credentials, arguments, user_urn)

class ABACQueryGenerator(object): 
    def generate_query(self, client_cert, credentials, arguments, urn):
        raise CHAPIv1NotImplementedError("Absract Base class: ABACQueryGenerator")

# Is client (C) a member of the project associated with the given slice URN?
class QueryProjectMember(ABACQueryGenerator):
    def generate_query(self, client_cert, credentials, arguments, user_urn):
        urn_project_names = lookup_project_names_for_user(user_urn)
        return [["C", "is_member_%s" % str(urn_project_name)]  for urn_project_name in urn_project_names]

# Is client (C) a member of the project associated
class QueryProjectMemberBySliceURN(ABACQueryGenerator):
    def generate_query(self, client_cert, credentials, arguments, slice_urn):
        urn_project_name = lookup_project_name_for_slice(slice_urn)
        return [["C", "is_member_%s" %  str(urn_project_name)]]

# Pre-processor for method invocations
class InvocationCheck(object):

    # Raise an AUTHENTICATION_ERROR if there is something wrong about the 
    # certs and credentials passed to the call
    def authenticate_call(self, client_cert, credentials):
        # *** WRITE ME
        pass

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    def validate_arguments(self, options, arguments):
        # Method-specific logic
        pass

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/argumentspassed to the call
    def authorize_call(self, client_cert, method, credentials, arguments):
        raise CHAPIv1NotImplementedError("Absract Base class: RowCheck")

    # Authenticate the call, validate arguments and check authorization
    def validate(self, client_cert, method, credentials, options, arguments):
        self.authenticate_call(client_cert, credentials)
        self.validate_arguments(options, arguments)
        self.authorize_call(client_cert, method, credentials, arguments)

class RowCheck(object):
    def permit(self, client_cert, credentials, urn):
        raise CHAPIv1NotImplementedError("Absract Base class: RowCheck")
        

# An ABAC check gathers a set of assertions and then validates a set of queries
# If all queries pass, then the overall Check passes
class ABACCheck(object):

    def __init__(self, asserters, queries):
        self._asserters = asserters
        self._queries = queries
        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")
#        print "KEY = " + key_file
#        print "CERT = " + cert_file

    def compute(self, client_cert, credentials, arguments, urn):

        # Bind entities : C = client_cert, ME = auth_cert, auth_key
        certs_by_name = {'C' : client_cert, 'ME' : self.cert_file}
        abac_manager = \
            ABACManager(certs_by_name = {"C" : client_cert}, \
                            cert_files_by_name = {"ME" : self.cert_file}, \
                            key_files_by_name = {"ME" : self.key_file})

        # Gather all assertions about context
        for asserter in self._asserters:
            asserter.generate_assertions(abac_manager, client_cert, credentials, arguments, urn)

        # Compute queries from ABAC: If any pass, we permit.
        for query in self._queries:
            if isinstance(query, ABACQueryGenerator):
                # A query generate can return a list of queries, any one of which is sufficient to accept
                target_roles = query.generate_query(client_cert, credentials, arguments, urn)
            else:
                target_roles = [query]

            for target_role in target_roles:
                q_target = target_role[0]
                q_role = target_role[1]
                query_expression = "ME.%s<-%s" % (q_role, q_target)

                ok, proof = abac_manager.query(query_expression)
                print "query : " + q_target + " " + q_role + " " + str(ok)
                if ok:
                    print "Proof " + "\n".join(abac_manager.pretty_print_proof(proof))
                    return True
        return False

# For testing whether a method invocation is permitted
class ABACInvocationCheck(ABACCheck, InvocationCheck):

    def __init__(self, asserters, queries):
        ABACCheck.__init__(self, asserters, queries)

    def authorize_call(self, client_cert, method, credentials, arguments):
        urn = None
        if arguments.has_key('slice_urn'):
            urn = arguments['slice_urn']
        elif arguments.has_key('user_urn'):
            urn = arguments['user_urn']
        if not self.compute(client_cert, credentials, arguments, urn):
            raise CHAPIv1AuthorizationError("Call not authorized: " + method)

# For testing whether a given data row is permitted to be exposed to caller
class ABACRowCheck(ABACCheck, RowCheck):
    def __init__(self, asserters, queries): 
        ABACCheck.__init__(self, asserters, queries)

    def permit(self, client_cert, credentials, urn):
        return self.compute(client_cert, credentials, {}, urn)

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
        print "ABACGuardBase.validate_call : " + method + " " + str(arguments) + " " + str(options)


        argument_check = self.get_argument_check(method)
        if argument_check:
            argument_check.validate(options, arguments)
        
        invocation_check = self.get_invocation_check(method)
        if invocation_check:
            invocation_check.validate(client_cert, method, \
                                          credentials, options, arguments)

    def protect_results(self, client_cert, method, credentials, results):
        print "ABACGuardBase.protect_results : " + method + " " + str(results)
        protected_results = results
        row_check = self.get_row_check(method)
        if row_check:
            protected_results = {}
            for urn in results.keys():
                urn_result = results[urn]
                print "URN = " + urn + " RES = " + str(urn_result)
                if row_check.permit(client_cert, credentials, urn):
                    protected_results[urn] = urn_result
        return protected_results

