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
from ABACGuard import ABACGuardBase
from chapi.Exceptions import *
from sqlalchemy import *
from datetime import *
from dateutil.relativedelta import relativedelta
from tools.dbutils import *
from tools.cert_utils import *

cs_logger = amsoil.core.log.getLogger('csv1')
xmlrpc = pm.getService('xmlrpc')

# Support for GENI Portal/Clearinghouse "Credential Store" a repository
# of assertions from which privileges can be derived

class CSv1Handler(HandlerBase):

    def __init__(self):
        super(CSv1Handler, self).__init__(cs_logger)

    def get_attributes(self, principal, context_type, context, \
                           credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_attributes'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,  \
                                          {'principal' : principal, \
                                               'context_type' : context_type, \
                                               'context' : context})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options)
            return self._delegate.get_attributes(client_cert, principal, \
                                                     context_type, context, \
                                                     credentials, options)
        except Exception as e:
            return self._errorReturn(e)

    def get_permissions(self, principal, credentials, options):
        client_cert = self.requestCertificate()
        method = 'get_permissions'
        try:
            self._guard.validate_call(client_cert, method, \
                                          credentials, options,  \
                                          {'principal' : principal})
            client_cert, options = \
                self._guard.adjust_client_identity(client_cert, \
                                                       credentials, options);
            return self._delegate.get_permissions(client_cert, principal, \
                                                      credentials, options)
        except Exception as e:
            return self._errorReturn(e)


class CSv1Delegate(DelegateBase):

    def __init__(self):
        super(CSv1Delegate, self).__init__(cs_logger)
        self.db = pm.getService('chdbengine')

    def get_attributes(self, client_cert, principal, context_type, context, \
                           credentials, options):

        session = self.db.getSession()

        q = session.query(self.db.CS_ATTRIBUTE_TABLE.c.name, self.db.CS_ASSERTION_TABLE.c.context)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.attribute == self.db.CS_ATTRIBUTE_TABLE.c.id)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.principal == principal)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.context_type == context_type)
        if context:
            q = q.filter(self.db.CS_ASSERTION_TABLE.c.context == context)

        rows = q.all()
        session.close()
        response = [(str(row[0]), str(row[1])) for row in rows] # Convert from unicode to string
        print "GA : P=%s CT=%s CID=%s OPTS=%s\n" % (principal, context_type, context, options)
        print "GA.response = " + str(response);
        return self._successReturn(response)


    def get_permissions(self, client_cert, principal, credentials, options):
        session = self.db.getSession()

        q = session.query(self.db.CS_ACTION_TABLE.c.name, self.db.CS_ASSERTION_TABLE.c.context_type, \
                              self.db.CS_ASSERTION_TABLE.c.context)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.principal == principal)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.attribute == self.db.CS_POLICY_TABLE.c.attribute)
        q = q.filter(self.db.CS_ASSERTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)
        q = q.filter(self.db.CS_ACTION_TABLE.c.privilege == self.db.CS_POLICY_TABLE.c.privilege)
        q = q.filter(self.db.CS_ACTION_TABLE.c.context_type == self.db.CS_POLICY_TABLE.c.context_type)

        rows = q.all()
        session.close()
        # Convert from unicode to string
        response = [{'name' : str(row.name), 'context_type' : str(row.context_type), 'context' : str(row.context)} for row in rows] 
        return self._successReturn(response)

# Simple guard, just to capture speaks-for implementation
# *** WRITE ME ***
class CSv1Guard(ABACGuardBase):
    def __init__(self):
        ABACGuardBase.__init__(self)

    def get_argument_check(self, method):
        return None

    def get_invocation_check(self, method):
        return None

    def get_row_check(self, method):
        return None


