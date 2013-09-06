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
from chapi.Exceptions import *
from sqlalchemy import *
from datetime import *
from dateutil.relativedelta import relativedelta
from tools.dbutils import *
from ABACGuard import ABACGuardBase

clientauth_logger = amsoil.core.log.getLogger('clientauthv1')
xmlrpc = pm.getService('xmlrpc')

# Class for managing the set of clients (tools) authorized by users
# This should go away when 'speaks-for' is in place

class ClientAuthv1Handler(HandlerBase):

    def __init__(self):
        super(ClientAuthv1Handler, self).__init__(clientauth_logger)

    def list_clients(self):
        return self._delegate.list_clients()

    def list_authorized_clients(self, member_id):
        client_cert = self.requestCertificate()
        try:
            results = self._delegate.list_authorized_clients(client_cert, \
                                                                 member_id)
            return results;
        except Exception as e:
            return self._errorReturn(e)

    def authorize_client(self, member_id, client_urn, authorize_sense):
        client_cert = self.requestCertificate()
        try:
            results = self._delegate.authorize_client(client_cert, \
                                                           member_id, \
                                                           client_urn, \
                                                           authorize_sense)
            return results;
        except Exception as e:
            return self._errorReturn(e)

class ClientAuthv1Delegate(DelegateBase):

    def __init__(self):
        super(ClientAuthv1Delegate, self).__init__(clientauth_logger)
        self.db = pm.getService('chdbengine')

    # Dictionary of client_name => client_urn
    def list_clients(self):
        session = self.db.getSession()
        q = session.query(self.db.MA_CLIENT_TABLE)
        rows = q.all()
        session.close()
        entries = {}
        for row in rows:
            entries[row.client_name] = row.client_urn
        return self._successReturn(entries)

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id):
        session = self.db.getSession()
        q = session.query(self.db.INSIDE_KEY_TABLE.c.client_urn)
        q = q.filter(self.db.INSIDE_KEY_TABLE.c.member_id == member_id)
        rows = q.all()
        session.close()
        entries = [str(row.client_urn) for row in rows]
        return self._successReturn(entries)

    # Authorize/deauthorize a tool with respect to a user
    # *** WRITE ME
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense):
        raise CHAPIv1NotImplementedError('')

# *** WRITE ME
class ClientAuthv1Guard(ABACGuardBase):
    def __init__(self):
        ABACGuardBase.__init__(self)

