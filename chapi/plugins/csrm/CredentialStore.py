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
from CHDatabaseEngine import *
from chapi.DelegateBase import DelegateBase
from chapi.HandlerBase import HandlerBase
from ABACGuard import *
from chapi.Exceptions import *
from sqlalchemy import *
from datetime import *
from dateutil.relativedelta import relativedelta
from tools.guard_utils import *
from tools.dbutils import *
from tools.cert_utils import *
from tools.chapi_log import *
from tools.geni_constants import *

cs_logger = amsoil.core.log.getLogger('csv1')
xmlrpc = pm.getService('xmlrpc')

# Support for GENI Portal/Clearinghouse "Credential Store" a repository
# of assertions from which privileges can be derived

class CSv1Handler(HandlerBase):

    def __init__(self):
        super(CSv1Handler, self).__init__(cs_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        chapi_log_exception(CS_LOG_PREFIX, e)
        return super(CSv1Handler, self)._errorReturn(e)

    def get_attributes(self, principal, context_type, context, \
                           credentials, options):
        if context == 'None': context = None # For testing with the client
        client_cert = self.requestCertificate()
        method = 'get_attributes'
        args = {'principal' : principal, \
                    'context_type' : context_type, \
                    'context' : context}
        chapi_log_invocation(CS_LOG_PREFIX, method, credentials, options, args)
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,  args)
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            result = self._delegate.get_attributes(client_cert, principal, \
                                                       context_type, context, \
                                                       credentials, options)
            chapi_log_result(CS_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)

    def get_permissions(self, principal, credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_permissions'
        args = {'principal' : principal}
        chapi_log_invocation(CS_LOG_PREFIX, method, credentials, options, args)
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options, args)
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options);
            result = self._delegate.get_permissions(client_cert, principal, \
                                                        credentials, options)
            chapi_log_result(CS_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)


class CSv1Delegate(DelegateBase):

    def __init__(self):
        super(CSv1Delegate, self).__init__(cs_logger)
        self.db = pm.getService('chdbengine')

    def get_attributes(self, client_cert, principal, context_type, context, \
                           credentials, options):

        session = self.db.getSession()

        # Project attributes
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.name, self.db.PROJECT_MEMBER_TABLE.c.project_id)
        q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.member_id == principal)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.id == self.db.PROJECT_MEMBER_TABLE.c.role)
        if context:
            q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.project_id == context)

        proj_rows = q.all()

        print "PROJ = %d" % len(proj_rows)

        # Slice attributes
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.name, self.db.SLICE_MEMBER_TABLE.c.slice_id)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.member_id == principal)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.id == self.db.SLICE_MEMBER_TABLE.c.role)
        if context:
            q = q.filter(self.db.SLICE_MEMBER_TABLE.c.slice_id == context)

        slice_rows = q.all()
#        print "SLICE = %d" % len(slice_rows)

        # Operator attributes
        operator_rows = []
        if not context:
            q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.name)
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'OPERATOR')
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == principal)
            operator_rows = q.all()
#            print "OPS = %d" % len(operator_rows)

        # Project lead attributes
        project_lead_rows = []
        if not context and int(context_type) == RESOURCE_CONTEXT:
            q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.name)
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == principal)
            project_lead_rows = q.all()
#            print "PIs = %d" % len(project_lead_rows)

        session.close()
        rows = proj_rows + slice_rows + operator_rows + project_lead_rows

        response = []
        for row in rows:
            if len(row) > 1:
                response.append((str(row[0]), str(row[1])))
            else:
                response.append((str(row[0]), None))

        return self._successReturn(response)

    # Return row.context if it has, otherwise None
    def get_context(self, row):
        if hasattr(row, 'context'):
            return str(row.context)
        return None


    def get_permissions(self, client_cert, principal, credentials, options):
        session = self.db.getSession()

        q = session.query(self.db.CS_ACTION_TABLE.c.name, 
                          self.db.CS_ACTION_TABLE.c.context_type, 
                          self.db.PROJECT_MEMBER_TABLE.c.project_id.label('context'))
        q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.member_id == principal)
        q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.role == self.db.CS_POLICY_TABLE.c.attribute)
        q = q.filter(self.db.CS_ACTION_TABLE.c.privilege == self.db.CS_POLICY_TABLE.c.privilege)
        q = q.filter(self.db.CS_POLICY_TABLE.c.context_type == PROJECT_CONTEXT)
        q = q.filter(self.db.CS_ACTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)

        project_rows = q.all()
#        print "PROJECT_ROWS = %d " % len(project_rows)

        q = session.query(self.db.CS_ACTION_TABLE.c.name, 
                          self.db.CS_ACTION_TABLE.c.context_type, 
                          self.db.SLICE_MEMBER_TABLE.c.slice_id.label('context'))
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.member_id == principal)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.role == self.db.CS_POLICY_TABLE.c.attribute)
        q = q.filter(self.db.CS_ACTION_TABLE.c.privilege == self.db.CS_POLICY_TABLE.c.privilege)
        q = q.filter(self.db.CS_POLICY_TABLE.c.context_type == SLICE_CONTEXT)
        q = q.filter(self.db.CS_ACTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)

        slice_rows = q.all()
#        print "SLICE = %d " % len(slice_rows)

        q = session.query(self.db.CS_ACTION_TABLE.c.name, 
                          self.db.CS_POLICY_TABLE.c.context_type)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'OPERATOR')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == principal)
        q = q.filter(self.db.CS_POLICY_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
        q = q.filter(self.db.CS_ACTION_TABLE.c.privilege == self.db.CS_POLICY_TABLE.c.privilege)
        q = q.filter(self.db.CS_ACTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)

        operator_rows = q.all()
#        print "OPERATOR = %d " % len(operator_rows)

        q = session.query(self.db.CS_ACTION_TABLE.c.name, 
                          self.db.CS_POLICY_TABLE.c.context_type)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == principal)
        q = q.filter(self.db.CS_POLICY_TABLE.c.attribute == LEAD_ATTRIBUTE)
        q = q.filter(self.db.CS_POLICY_TABLE.c.context_type == RESOURCE_CONTEXT)
        q = q.filter(self.db.CS_ACTION_TABLE.c.privilege == self.db.CS_POLICY_TABLE.c.privilege)
        q = q.filter(self.db.CS_ACTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)
        
        lead_rows = q.all()
#        print "LEAD = %d " % len(lead_rows)

        rows = project_rows + slice_rows + operator_rows + lead_rows

        session.close()
        # Convert from unicode to string
        response = [( str(row.name), str(row.context_type), self.get_context(row) ) for row in rows] 
        return self._successReturn(response)

# Guard on Credential Store methods
# Essentially you can get attributes or permissions for yourself, 
# or if you are an authority
class CSv1Guard(ABACGuardBase):
    def __init__(self):
        ABACGuardBase.__init__(self)

    # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'get_attributes' : None,
        'get_permissions' : None
        }

    INVOCATION_CHECK_FOR_METHOD = \
        {
        'get_attributes' : \
            SubjectInvocationCheck([
                "ME.MAY_GET_ATTRIBUTES<-ME.IS_AUTHORITY",
                "ME.MAY_GET_ATTRIBUTES_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, principal_extractor),
        'get_permissions' : \
            SubjectInvocationCheck([
                "ME.MAY_GET_PERMISSIONS<-ME.IS_AUTHORITY",
                "ME.MAY_GET_PERMISSIONS_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, principal_extractor),
        }


    # Lookup argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None



