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

from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from CHDatabaseEngine import CHDatabaseEngine
import amsoil.core.pluginmanager as pm
from chapi.GuardBase import GuardBase
from chapi.Exceptions import *
import sfa.trust.certificate;
from ABAC import *
from tools.ABACManager import ABACManager

# Pre-processor for method invocations
class SAv1InvocationGuard:

    def __init__(self):
        self.db_engine = pm.getService('chdbengine')

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

    q = session.query(db.MEMBER_ATTRIBUTE_TABLE, db.PROJECT_TABLE, db.PROJECT_MEMBER_TABLE)
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

# Post-processor for invocations
# For individual rows that were computed, are they permitted to be
# seen by caller?
class SAv1RowGuard:

    def __init__(self):
        self.db_engine = pm.getService('chdbengine')

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
        config = pm.getService('config')
        key_file = config.get("chapiv1rpc.ch_key")
        cert_file = config.get("chapiv1rpc.ch_cert")
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
            {'role' : str('is_member_%s' % slice_project_name), 'target' : 'C'}
            ]
        for q in queries:
            q_role = q['role']
            q_target = q['target']
            ok, proof =  abac_manager.query(q_target, q_role)
            if ok:
                print "Proof " + "\n".join(abac_manager.pretty_print_proof(proof))
                return
        raise CHAPIv1AuthorizationError("Caller %s is not allowed to access slice_membership for slice %s" % (user_urn, slice_urn))

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
            {'role' : str('is_member_%s' % urn_project_name), 'target' : 'C'}
            ]
        for q in queries:
            q_role = q['role']
            q_target = q['target']
            ok, proof = abac_manager.query(q_target, q_role)
            if ok:
                print "Proof " + "\n".join(abac_manager.pretty_print_proof(proof))
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
