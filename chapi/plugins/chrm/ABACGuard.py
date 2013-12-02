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
from syslog import syslog
import amsoil.core.pluginmanager as pm
from tools.chapi_log import *
from tools.mapped_tables import MemberAttribute

logger = amsoil.core.log.getLogger('ABAC')


# Pre-processor for method invocations
class InvocationCheck(object):

    # Raise an ARGUMENT_ERROR if there is something wrong about the 
    # arguments passed to method
    # Return dictionary of {subject_type : subjects}
    def validate_arguments(self, client_cert, method, options, arguments):
        # Method-specific logic
        return None

    # Raise an AUTHORIZATION_ERROR if there is something wrong about the 
    # certs and credentials and options/arguments passed to the call
    # and subjects extracted from validate_arguments call
    def authorize_call(self, client_cert, method, credentials, options, \
                           arguments, subjects ):
        raise CHAPIv1NotImplementedError("Abstract Base class: InvocationCheck")

    # Validate arguments and check authorization
    def validate(self, client_cert, method, credentials, options, arguments):
        subjects = self.validate_arguments(client_cert, method, \
                                               options, arguments)
        self.authorize_call(client_cert, method, credentials, \
                                options, arguments, subjects)

# Class that determines if the caller has the right to invoke a given method on all
# the subjects of a given method invocation
class SubjectInvocationCheck(InvocationCheck):

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
    def validate_arguments(self, client_cert, method, options, arguments):
        subjects = {}
        if self._subject_extractor:
            subjects = self._subject_extractor(options, arguments)
#            if not subjects or len(subjects) == 0:
#                raise CHAPIv1ArgumentError("No subjects supplied to call %s" % method);
            if subjects and len(subjects) > 1:
                raise CHAPIv1ArgumentError("Can't provide mixture of subject types for call %s: %s" % \
                                               (method, subjects.keys()))
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
                           arguments, subjects):
        abac_manager =  ABACManager(certs_by_name = {"CALLER" : client_cert}, 
                                    cert_files_by_name = {"ME" : self.cert_file}, 
                                    key_files_by_name = {"ME" : self.key_file},
                                    manage_context = False)
        #abac_manager._verbose = True

        client_urn = get_urn_from_cert(client_cert)

        # Gather context-free assertions for caller
        if lookup_operator_privilege(client_urn):
            abac_manager.register_assertion("ME.IS_OPERATOR<-CALLER")
        if lookup_pi_privilege(client_urn):
            abac_manager.register_assertion("ME.IS_PI<-CALLER")
        abac_manager.register_assertion("ME.IS_%s<-CALLER" % flatten_urn(client_urn))
        if lookup_authority_privilege(client_urn):
            abac_manager.register_assertion("ME.IS_AUTHORITY<-CALLER")

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
                for attribute_extractor in self._attribute_extractors:
                    attribute_extractor(client_urn, subjects_of_type, \
                                        subject_type, options, abac_manager)

            # Register policies relative to the subjects
            # And try to prove that the user may call the method, 
            # given the policies
            # About who can call the method and the attibutes of the caller
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
                        syslog("Testing ABAC query %s OK = %s" % (query, ok))
                        chapi_info('', "Testing ABAC query %s OK = %s" % (query, ok))
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
            if not ok:
                template = "Caller not authorized to call method %s " + \
                    "with options %s arguments %s query %s"
                raise CHAPIv1AuthorizationError(template % \
                        (method, options, arguments, query));


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


    def validate_call(self, client_cert, method, credentials, options, arguments = {}):
#        print "ABACGuardBase.validate_call : " + method + " " + str(arguments) + " " + str(options)

        self.user_check(client_cert)

        argument_check = self.get_argument_check(method)
        if argument_check:
            argument_check.validate(options, arguments)
        
        invocation_check = self.get_invocation_check(method)
        if invocation_check:
            invocation_check.validate(client_cert, method, \
                                          credentials, options, arguments)

    def user_check(self, client_cert):
        client_urn = get_urn_from_cert(client_cert)
        client_uuid = get_uuid_from_cert(client_cert)
        client_name = get_name_from_urn(client_urn)

        session = self.db.getSession()
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == client_uuid).\
            filter(MemberAttribute.name == '_GENI_MEMBER_ENABLED')
        rows = q.all()
        is_enabled = (len(rows)==0 or rows[0][0] == 'y')
        session.close()

        if is_enabled:
            #syslog("UC: user '%s' (%s) enabled" % (client_name, client_urn))
            pass
        else:
            syslog("UC: user '%s' (%s) disabled" % (client_name, client_urn))
            raise CHAPIv1AuthorizationError("User %s (%s) disabled" % (client_name, client_urn));

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
