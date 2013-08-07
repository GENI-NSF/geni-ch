from CHDatabaseEngine import CHDatabaseEngine
import amsoil.core.pluginmanager as pm
from  sqlalchemy import *
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
import types
from ABAC import *
from tools.ABACManager import ABACManager

# Pre-processor for method invocations
class SAv1InvocationGuard(object):

    def __init__(self):
        self._db_engine = pm.getService('chdbengine')
        self._client_cert = None

    def setClientCert(self, client_cert):
        self._client_cert = client_cert

    # Raise an AUTHENTICATION_ERROR if there is something wrong about the 
    # certs and credentials passed to the call
    def authenticate_call(self, client_cert, credentials):
        # *** WRITE ME
        pass

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    def validate_arguments(self, options, args):
        # Method-specific logic
        pass

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/argumentspassed to the call
    def authorize_call(self, client_cert, credentials, args):
        # Method-specific logic
        pass

    # Authenticate the call, validate arguments and check authorization
    def validate(self, client_cert, credentials, options, args):
        self.authenticate_call(client_cert, credentials)
        self.validate_arguments(options, args)
        self.authorize_call(client_cert, credentials, args)

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

class ABACAsserter(object): pass

class OperatorAsserter(ABACAsserter):
    def generate_assertions(self, abac_manager, client_cert, credentials, args):
        user_urn = extract_user_urn(client_cert)
        is_operator = lookup_operator_privilege(user_urn)
        if is_operator:
            abac_manager.register_assertion("SA.is_operator<-C")

class ProjectMemberAsserterByURN(ABACAsserter):
    def generate_assertions(self, abac_manager, client_cert, credentials, args):
        user_urn = args['urn']
        user_project_names = lookup_project_names_for_user(user_urn)
        for user_project_name in user_project_names:
            assertion = "SA.is_member_%s<-C" % str(user_project_name)
            abac_manager.register_assertion(assertion)

class ProjectMemberAsserterByCert(ProjectMemberAsserterByURN):
    def generate_assertions(self, abac_manager, client_cert, credentials, args):
        args['urn'] = extract_user_urn(client_cert)
        super(self.__class__, self).generate_assertions(abac_manager, \
                                                            client_cert, credentials, args)

class QueryGenerator(object): pass

# Is client (C) a member of the project associated with the given slice URN?
class QueryProjectMember(QueryGenerator):
    def generate_query(self, client_cert, credentials, args):
        slice_urn = args['urn']
        urn_project_name = lookup_project_name_for_slice(slice_urn)
        return "C", "is_member_%s" %  str(urn_project_name)

# Is client (C) a member of the project associated
class QueryProjectMemberBySliceURN(QueryGenerator):
    def generate_query(self, client_cert, credentials, args):
        slice_urn = args['slice_urn']
        urn_project_name = lookup_project_name_for_slice(slice_urn)
        return "C", "is_member_%s" %  str(urn_project_name)

class SAv1ABACGuard(SAv1InvocationGuard):

    def __init__(self, asserters, queries):
        self._asserters = asserters
        self._queries = queries
        self.config = pm.getService('config')
        self.key_file = self.config.get("chapiv1rpc.ch_key")
        self.cert_file = self.config.get("chapiv1rpc.ch_cert")
#        print "KEY = " + key_file
#        print "CERT = " + cert_file

    def compute(self, client_cert, credentials, args):
        # Bind entities : C = client_cert, SA = sa_cert, sa_key
        certs = {'C' : client_cert}
        abac_manager = ABACManager('SA', self.cert_file, self.key_file, certs)

        # Gather all assertions about context
        for asserter in self._asserters:
            asserter.generate_assertions(abac_manager, client_cert, credentials, args)

        # Compute queries from ABAC: If any pass, we permit.
        for query in self._queries:
            if isinstance(query, QueryGenerator):
                q_target, q_role = query.generate_query(client_cert, credentials, args)
            else:
                q_target = query[0]
                q_role = query[1]

            ok, proof = abac_manager.query(q_target, q_role)
            if ok:
                print "Proof " + "\n".join(abac_manager.pretty_print_proof(proof))
                return True
        return False

# For testing whether a method invocation is permitted
class SAv1ABACInvocationGuard(SAv1ABACGuard):

    def __init__(self, asserters, queries):
        super(self.__class__, self).__init__(asserters, queries)

    def authorize_call(self, client_cert, credentials, args):
        return self.compute(client_cert, credentials, args = args)

# For testing whether a given data row is permitted to be exposed to caller
class SAv1ABACRowGuard(SAv1ABACGuard):
    def __init__(self, asserters, queries): 
        super(self.__class__, self).__init__(asserters, queries)

    def permit(self, client_cert, credentials, urn):
        return self.compute(client_cert, credentials, args = {'urn' : urn})

INVOCATION_GUARDS_FOR_METHOD = \
    { 
    'lookup_slices' : 
    SAv1ABACInvocationGuard(asserters = [], queries = []),
    'lookup_slice_members' : 
    SAv1ABACInvocationGuard(asserters= [OperatorAsserter(), ProjectMemberAsserterByCert()],
                                queries = [["C", "is_operator"], QueryProjectMemberBySliceURN()])
    }

ROW_GUARDS_FOR_METHOD = \
    { 
    'lookup_slices' : 
    SAv1ABACRowGuard(asserters = [OperatorAsserter(), ProjectMemberAsserterByCert()],
                     queries = [["C", "is_operator"], QueryProjectMember()]) 
    }

class SAv1Guard(GuardBase):
    
    def __init__(self):
        super(self.__class__, self).__init__()

    def validate_call(self, client_cert, method, credentials, options, args):
        print "SAv1Guard.validate_call : " + method + " " + str(args) + " " + str(options)
        if INVOCATION_GUARDS_FOR_METHOD.has_key(method):
            invocation_guard = INVOCATION_GUARDS_FOR_METHOD[method]
            invocation_guard.setClientCert(client_cert)
            return invocation_guard.validate(client_cert, credentials, options, args)

    def protect_results(self, client_cert, method, credentials, results):
        print "SAv1Guard.protect_results : " + method + " " + str(results)
        protected_results = results
        if ROW_GUARDS_FOR_METHOD.has_key(method):
            protected_results = {}
            row_guard = ROW_GUARDS_FOR_METHOD[method]
            row_guard.setClientCert(client_cert)
            for urn in results.keys():
                urn_result = results[urn]
                if row_guard.permit(client_cert, credentials, urn):
                    protected_results[urn] = urn_result
        return protected_results
