#----------------------------------------------------------------------
# Copyright (c) 2011-2016 Raytheon BBN Technologies
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

import tools.pluginmanager as pm

from CHDatabaseEngine import *
from chapi.DelegateBase import DelegateBase
from chapi.HandlerBase import HandlerBase
from chapi.Exceptions import *
from chapi.MethodContext import *
from ABACGuard import *

from tools.dbutils import *
from tools.geni_constants import context_type_names
from tools.chapi_log import *
from tools.cert_utils import get_email_from_cert
from tools.guard_utils import *
from tools.policy_file_checker import PolicyFileChecker

from sqlalchemy import *
from datetime import datetime
from dateutil.relativedelta import relativedelta


logging_logger = logging.getLogger('logv1')
xmlrpc = pm.getService('xmlrpc')

class Loggingv1Handler(HandlerBase):

    def __init__(self):
        super(Loggingv1Handler, self).__init__(logging_logger)

    # Enter new logging entry in database for given sets of attributes
    def log_event(self, message, attributes, credentials, options,
                  session=None):
        with MethodContext(self, LOG_LOG_PREFIX, 'log_event',
                           {'message' : message, 'attributes' : attributes},
                           credentials, options, read_only=False,
                           session=session) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.log_event(mc._client_cert,
                                             message, attributes,
                                             credentials, options,
                                             mc._session)
        return mc._result

    # Get all entries written by given author in most recent hours
    def get_log_entries_by_author(self, user_id, num_hours, credentials,
                                  options):
        with MethodContext(self, LOG_LOG_PREFIX, 'get_log_entries_by_author',
                           {'user_id' : user_id, 'num_hours' : num_hours},
                           credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_log_entries_by_author(mc._client_cert,
                                                             user_id, 
                                                             num_hours,
                                                             credentials,
                                                             options,
                                                             mc._session)
        return mc._result


    # Get all entries written for context type/id in most recent hours
    def get_log_entries_for_context(self, context_type, context_id, num_hours,
                                    credentials, options):
        with MethodContext(self, LOG_LOG_PREFIX, 'get_log_entries_for_context',
                           {'context_type' : context_type, 
                            'context_id' : context_id, 
                            'num_hours' : num_hours},
                           credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_log_entries_for_context(mc._client_cert,
                                                               context_type,
                                                               context_id,
                                                               num_hours,
                                                               credentials,
                                                               options,
                                                               mc._session)
        return mc._result

    # Get all log entries corresponding to the UNION of a set
    # of context/id pairs in most recent hours
    def get_log_entries_by_attributes(self, attribute_sets, num_hours,
                                      credentials, options):
        with MethodContext(self, LOG_LOG_PREFIX, 'get_log_entries_by_attributes',
                           {'attribute_sets' : attribute_sets,
                            'num_hours' : num_hours},
                           credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_log_entries_by_attributes(mc._client_cert,
                                                               attribute_sets,
                                                               num_hours,
                                                                 credentials,
                                                                 options,
                                                               mc._session)
        return mc._result

    # Get set of attributes for given log entry
    def get_attributes_for_log_entry(self, event_id, credentials, options):
        with MethodContext(self, LOG_LOG_PREFIX, 
                           'get_attributes_for_log_entry',
                           {'event_id' : event_id},
                           credentials, options, read_only=True) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.get_attributes_for_log_entry(mc._client_cert,
                                                                event_id,
                                                                credentials,
                                                                options,
                                                                mc._session)
        return mc._result

class Loggingv1Delegate(DelegateBase):

    columns = ['id', 'user_id', 'message', 'event_time']
    field_mapping = {'id' : 'id', 'user_id' : 'user_id', \
                         'message' : 'message', 'event_time' : 'event_time'}

    attribute_columns = ['event_id', 'attribute_name', 'attribute_value']
    attribute_field_mapping = {'event_id': 'event_id', \
                                   'attribute_name' : 'attribute_name', \
                                   'attribute_value' : 'attribute_value'}
    def __init__(self):
        super(Loggingv1Delegate, self).__init__(logging_logger)
        self.db = pm.getService('chdbengine')

    # The attributes argument is a dictionary of name/value pairs
    def log_event(self, client_cert, message, attributes, credentials, options,
                  session, none_user_id=False):

        now = datetime.utcnow()
        # Record the event
        # Insert into logging_entry (event_time, user_id, message) values
        # (now, user_id, message)
        user_id = None
        if not none_user_id:
            user_id = get_uuid_from_cert(client_cert)

        if user_id:
            ins = self.db.LOGGING_ENTRY_TABLE.insert().values(event_time=str(now), user_id=str(user_id), message=message)
        else:
            ins = self.db.LOGGING_ENTRY_TABLE.insert().values(event_time=str(now), message=message)
        result = session.execute(ins)
        # Grab the event
        event_id = result.inserted_primary_key[0]
        # Register the attributes
        for key, value in attributes.iteritems():
            # Insert into logging_entry_attribute_table 
            # (event_id, attribute_name, attribute_value) 
            # values (event_id, key, value)
            ins = self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.insert().values(event_id = event_id, attribute_name=key, attribute_value=str(value))
            result = session.execute(ins)

        return self._successReturn(True)

    def get_log_entries_by_author(self, client_cert, user_id, 
                                  num_hours, credentials, options, session):

        q = session.query(self.db.LOGGING_ENTRY_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.user_id == user_id)
        min_event_time = datetime.utcnow() - relativedelta(hours=num_hours)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.event_time >= min_event_time)
        rows = q.all()
        entries = [construct_result_row(row, self.columns, 
                                        self.field_mapping, session) \
                       for row in rows]
        return self._successReturn(entries)

    def get_log_entries_for_context(self, client_cert, context_type, 
                                    context_id, num_hours, credentials,
                                    options, session):

        q = session.query(self.db.LOGGING_ENTRY_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.id == self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.event_id)
        min_event_time = datetime.utcnow() - relativedelta(hours=num_hours)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.event_time >= min_event_time)
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_name == context_type_names[context_type])
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_value == context_id)
        rows = q.all()
        entries = [construct_result_row(row, self.columns, \
                                            self.field_mapping, session) \
                       for row in rows]
        return self._successReturn(entries)

    def get_log_entries_by_attributes(self, client_cert, attribute_sets, 
                                      num_hours, credentials, options, session):

        q = session.query(self.db.LOGGING_ENTRY_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.id == self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.event_id)
        min_event_time = datetime.utcnow() - relativedelta(hours=num_hours)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.event_time >= min_event_time)
        conditions = []
        for attribute_set in attribute_sets:
            key = attribute_set.keys()[0]
            value = attribute_set[key]
            conditions.append(and_(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_name == key, \
                                       self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_value == value))
        or_condition = or_(*conditions)
        q = q.filter(or_condition)
        q = q.distinct()
        rows = q.all()
        entries = [construct_result_row(row, self.columns, 
                                        self.field_mapping, session) \
                       for row in rows]
        return self._successReturn(entries)


    def get_attributes_for_log_entry(self, client_cert, event_id, credentials,
                                     options, session):

        q = session.query(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.event_id == event_id)
        rows = q.all()
        entries = [construct_result_row(row, self.attribute_columns, \
                                            self.attribute_field_mapping, \
                                            session) \
                       for row in rows]
        return self._successReturn(entries)



class Loggingv1Guard(ABACGuardBase):
    def __init__(self):
        ABACGuardBase.__init__(self)

        # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'log_event' : \
            SimpleArgumentCheck({'message' : 'STRING',
                                 'attributes' : 'ATTRIBUTE_SET'}),
        'get_log_entries_by_author' : \
            SimpleArgumentCheck({'user_id' : 'UID', 
                                 'num_hours' : 'POSITIVE'}),
        'get_log_entries_for_context' : \
            SimpleArgumentCheck({'context_type' : 'CONTEXT_TYPE', 
                                 'context_id' : 'UID', 
                                 'num_hours' : 'POSITIVE'}),
        'get_log_entries_by_attributes' : \
            None,
        'get_attributes_for_log_entry' : \
            None
        }

    INVOCATION_CHECK_FOR_METHOD = None

    # Name of policies file
    policies_filename = "/etc/geni-chapi/logging_policy.json"

    # Thread to check whether the policies file has changed
    policies_file_checker = None

    # Lookup argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):

        # Initiate file check thread
        if self.policies_file_checker == None:
            self.policies_file_checker = \
                PolicyFileChecker(self.policies_filename, 5, \
                                      self, LOG_LOG_PREFIX)
            self.policies_file_checker.start()

        if self.INVOCATION_CHECK_FOR_METHOD == None:
            policies = \
                parse_method_policies(Loggingv1Guard.policies_filename)
            self.INVOCATION_CHECK_FOR_METHOD = \
                create_subject_invocation_checks(self, policies)
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None



