from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
import amsoil.core.pluginmanager as pm
from ABAC import *
from ABACManager import ABACManager

# Pre-processor for method invocations
class SAv1InvocationGuard:

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
    def authorize_call(self, client_cert, credentials, options, args):
        # Method-specific logic
        pass

    # Authenticate the call, validate arguments and check authorization
    def validate(self, client_cert, credentials, options, args):
        self.authenticate_call(client_cert, credentials)
        self.validate_arguments(options, args)
        self.authorize_call(client_cert, credentials, options, args)

# Some helper methods

def extract_user_urn(user_urn):
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
    config = pm.getService('config')
    db_url_filename = config.get('chrm.db_url_filename')
    db_url = open(db_url_filename).read()
    db = create_engine(db_url)
    session_class = sessionmaker(bind=db)
    metadata = MetaData(db)
    session = session_class()

    SLICE_TABLE = Table('sa_slice', metadata, autoload=True)
    SLICE_MEMBER_TABLE = \
        Table('sa_slice_member', metadata, autoload=True)
    PROJECT_TABLE = Table('pa_project', metadata, autoload=True)
    PROJECT_MEMBER_TABLE = \
        Table('pa_project_member', metadata, autoload=True)
    MEMBER_ATTRIBUTE_TABLE = \
        Table('ma_member_attribute', metadata, autoload=True)

    q = session.query(MEMBER_ATTRIBUTE_TABLE, PROJECT_TABLE, PROJECT_MEMBER_TABLE)
    q = q.filter(PROJECT_TABLE.c.expired == 'f')
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(PROJECT_TABLE.c.project_id == PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.member_id == PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    
    project_names = [row.project_name for row in rows]
    return project_names

def lookup_operator_privilege(user_urn):
    config = pm.getService('config')
    db_url_filename = config.get('chrm.db_url_filename')
    db_url = open(db_url_filename).read()
    db = create_engine(db_url)
    session_class = sessionmaker(bind=db)
    metadata = MetaData(db)
    session = session_class()

    OPERATOR_ATTRIBUTE = 5
    SLICE_CONTEXT = 2

    ASSERTION_TABLE = Table('cs_assertion', metadata, autoload=True)
    MEMBER_ATTRIBUTE_TABLE = Table('ma_member_attribute', metadata, autoload=True)

    q = session.query(ASSERTION_TABLE, MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(ASSERTION_TABLE.c.context_type == SLICE_CONTEXT)
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.member_id == ASSERTION_TABLE.c.principal)
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    return len(rows) > 0

# Post-processor for invocations
# For individual rows that were computed, are they permitted to be
# seen by caller?
class SAv1RowGuard:
    def permit(self, client_cert, credentials, urn, urn_results):
        return True

class LookupSlicesInvocationGuard(SAv1InvocationGuard): 
    def authorize_call(self, client_cert, credentials, options, args):
        pass
        
class LookupSliceMembersInvocationGuard(SAv1InvocationGuard): 
    def authorize_call(self, client_cert, credentials, options, args):
        user_urn = extract_user_urn(client_cert)
        slice_urn = args['slice_urn']
        slice_project_name = lookup_project_name_for_slice(slice_urn)
#        print "PROJECT_NAME = " + slice_project_name
        # Bind entities : C = clien_cert, SA = sa_cert, sa_key
        certs = {'C' : client_cert}
        abac_manager = ABACManager("SA", cert_file, key_file, certs)

        # Gather assertions:
        # MA.is_member_Pi<-C for each project that C is a member of
        #  MA.is_operator<-C [If C is an operator]
        user_project_names = lookup_project_names_for_user(user_urn)
        for user_project_name in user_project_names:
            assertion = "SA.is_member_%s<-C" % user_project_name
            abac_manager.register_assertion(str(assertion))
        is_operator = lookup_operator_privilege(user_urn)
        if is_operator:
            abac_manager.register_assertion("SA.is_operator<-C")

        # Try to prove any of:
        #   MA.is_operator<- C
        #   MA.is_member_P <- C [For the project of the slice URN]
        queries = [
            {'role' : 'is_operator', 'target' : 'C'},
            {'role' : 'is_member_%s' % slice_project_name, 'target' : 'C'}
            ]
        for q in queries:
            q_role = q['role']
            q_target = q['target']
            if abac_manager.query(q_target, q_role):
                return 
        raise CHAPIv1AuthorizationError("Caller %s is not allowed to access slice_membership for slice %s" (user_urn, slice_urn))

class LookupSlicesRowGuard(SAv1RowGuard): 
    def permit(self, client_cert, credentials, urn, urn_results):
        urn_project_name = lookup_project_name_for_slice(urn)
#        print "PROJECT_NAME = " + urn_project_name
        config = pm.getService('config')
        key_file = config.get("chapiv1rpc.ch_key")
        cert_file = config.get("chapiv1rpc.ch_cert")
#        print "KEY = " + key_file
#        print "CERT = " + cert_file
#        print "CLIENT_CERT = " + str(client_cert)
        user_urn = extract_user_urn(client_cert)
        if user_urn == None:
            raise CHAPIv1AuthorizationError("Certificate has no subjectAltName publicid URN")

        # Bind entities : C = client_cert, SA = sa_cert, sa_key
        certs = {'C' : client_cert}
        abac_manager = ABACManager("SA", cert_file, key_file, certs)

        # Gather assertions:
        #   MA.is_operator<- C [If C is an operator]
        #   MA.is_member_Pi<-C [For each project that C is a member of]
        user_project_names = lookup_project_names_for_user(user_urn)
        for user_project_name in user_project_names:
            assertion = "SA.is_member_%s<-C" % user_project_name
            abac_manager.register_assertion(str(assertion))
        is_operator = lookup_operator_privilege(user_urn)
        if is_operator:
            abac_manager.register_assertion("SA.is_operator<-C")

        # Try to prove any of:
        #   MA.is_operator<- C
        #   MA.is_member_P <- C [For the project of the slice URN]
        queries = [
            {'role' : 'is_operator', 'target' : 'C'},
            {'role' : 'is_member_%s' % urn_project_name, 'target' : 'C'}
            ]
        for q in queries:
            q_role = q['role']
            q_target = q['target']
            if abac_manager.query(q_target, q_role):
                return True
        return False

INVOCATION_GUARDS_FOR_METHOD = \
    { 'lookup_slices' : LookupSlicesInvocationGuard(),
      'lookup_slice_members' : LookupSliceMembersInvocationGuard()
      }

ROW_GUARDS_FOR_METHOD = \
    { 'lookup_slices' : LookupSlicesRowGuard()
      }

class SAv1Guard(GuardBase):
    
    def __init__(self):
        super(SAv1Guard, self).__init__()

    def validate_call(self, client_cert, method, credentials, options, args):
        print "SAv1Guard.validate_call : " + method + " " + str(args) + " " + str(options)
        if INVOCATION_GUARDS_FOR_METHOD.has_key(method):
            invocation_guard = INVOCATION_GUARDS_FOR_METHOD[method]
            return invocation_guard.validate(client_cert, credentials, \
                                                 options, args)

    def protect_results(self, client_cert, method, credentials, results):
        print "SAv1Guard.protect_results : " + method + " " + str(results)
        protected_results = results
        if ROW_GUARDS_FOR_METHOD.has_key(method):
            protected_results = {}
            row_guard = ROW_GUARDS_FOR_METHOD[method]
            for urn in results.keys():
                urn_result = results[urn]
                if row_guard.permit(client_cert, credentials, urn, urn_result):
                    protected_results[urn] = urn_result
        return protected_results
