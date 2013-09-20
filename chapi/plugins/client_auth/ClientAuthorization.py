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
from ABACGuard import *
from tools.guard_utils import *
from tools.cert_utils import *

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
        method = 'list_authorized_clients'
        client_cert = self.requestCertificate()
        try:
            self._guard.validate_call(client_cert, method, \
                                          [], {}, {'member_id': member_id})
            results = self._delegate.list_authorized_clients(client_cert, \
                                                                 member_id)
            return results;
        except Exception as e:
            return self._errorReturn(e)

    def authorize_client(self, member_id, client_urn, authorize_sense):
        method = 'authorize_client'
        client_cert = self.requestCertificate()
        try:
            self._guard.validate_call(client_cert, method, [], {}, \
                                          {'member_id' : member_id, \
                                               'client_urn' : client_urn})
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
        self.cert = '/usr/share/geni-ch/km/km-cert.pem'
        self.key = '/usr/share/geni-ch/km/km-key.pem'
        self.logging_service = pm.getService('loggingv1handler')

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
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense):
        member_urn = convert_member_uid_to_urn(member_id)

        if authorize_sense:
            private_key, csr_file = make_csr()
            member_email = convert_member_uid_to_email(member_id)
            cert_pem = make_cert(member_id, member_email, member_urn, \
                                     self.cert, self.key, csr_file)

            signer_pem = open(self.cert).read()
            cert_chain = cert_pem + signer_pem

            # insert into MA_INSIDE_KEY_TABLENAME
            # (member_id, client_urn, certificate, private_key)
            # values 
            # (member_id, client_urn, cert, key)
            session = self.db.getSession()
            insert_values = {'client_urn' : client_urn, 'member_id' : str(member_id), \
                                 'private_key' : private_key, 'certificate' : cert_chain}
            ins = self.db.INSIDE_KEY_TABLE.insert().values(insert_values)
            session.execute(ins)
            session.commit()
            session.close()

            # log_event
            msg = "Authorizing client %s for member %s" % (client_urn, member_urn)
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, member_id)


        else:

            # delete from MA_INSIDE_KEY_TABLENAME
            # where member_id = member_id and client_urn = client_urn
            session = self.db.getSession()
            q = q.filter(self.db.INSIDE_KEY_TABLE.c.member_id == member_id)
            q = q.filter(self.db.INSIDE_KEY_TABLE.c.client_urn == client_urn)
            q = q.delete()
            session.commit()
            session.close()

            # log_event
            msg = "Deauthorizing client %s for member %s" % (client_urn, member_urn)
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, member_id)
        

def member_id_extractor(options, arguments):
    member_id = arguments['member_id']
    member_urn = convert_member_uid_to_urn(member_id)
    return {"MEMBER_URN" : member_urn}

# Guard for client authorization - only for authorities
class ClientAuthv1Guard(ABACGuardBase):

    # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'list_clients' : None,
        'list_authorized_clients' : None,
        'authorize_client' : None
        }

    # Set of invocation checks indexed by method name
    INVOCATION_CHECK_FOR_METHOD = \
        {
        'list_clients' : None,
        'list_authorized_clients' : \
            SubjectInvocationCheck([
                "ME.MAY_LIST_AUTHORIZED_CLIENTS<-ME.IS_AUTHORITY",
                "ME.MAY_LIST_AUTHORIZED_CLIENTS_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, member_id_extractor),
        'authorize_client' : \
            SubjectInvocationCheck([
                "ME.MAY_AUTHORIZE_CLIENT<-ME.IS_AUTHORITY",
                "ME.MAY_AUTHORIZE_CLIENT_$SUBJECT<-ME.IS_$SUBJECT"
                ], None, member_id_extractor)
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

