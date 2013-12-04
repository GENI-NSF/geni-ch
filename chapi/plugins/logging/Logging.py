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
import datetime
from dateutil.relativedelta import relativedelta
from tools.dbutils import *
from tools.geni_constants import context_type_names
from tools.chapi_log import *

logging_logger = amsoil.core.log.getLogger('logv1')
xmlrpc = pm.getService('xmlrpc')

class Loggingv1Handler(HandlerBase):

    def __init__(self):
        super(Loggingv1Handler, self).__init__(logging_logger)

    # Enter new logging entry in database for given sets of attributes
    # And logging user (author)
    def log_event(self, message, attributes, user_id):
        client_cert = self.requestCertificate()
        method = 'log_event'
        try:
            results = self._delegate.log_event(client_cert, \
                                                   message, \
                                                   attributes, user_id)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Get all entries written by given author in most recent hours
    def get_log_entries_by_author(self, user_id, num_hours):
        client_cert = self.requestCertificate()
        method = 'get_log_entries_by_author'
        try:
            results = \
                self._delegate.get_log_entries_by_author(client_cert, \
                                                             user_id, \
                                                             num_hours)
            return results
        except Exception as e:
            return self._errorReturn(e)


    # Get all entries written for context type/id in most recent hours
    def get_log_entries_for_context(self, context_type, context_id, num_hours):
        client_cert = self.requestCertificate()
        method = 'get_log_entries_for_context'
        try:
            results = \
                self._delegate.get_log_entries_for_context(client_cert, \
                                                                context_type, \
                                                                context_id, \
                                                                num_hours)
            return results
        except Exception as e:
            return self._errorReturn(e)


    # Get all log entries corresponding to the UNION of a set
    # of context/id pairs in most recent hours
    def get_log_entries_by_attributes(self, attribute_sets, num_hours):
        client_cert = self.requestCertificate()
        method = 'get_log_entries_by_attributes'
        try:
            results = \
                self._delegate.get_log_entries_by_attributes(client_cert, \
                                                                 attribute_sets, \
                                                                 num_hours)
            return results
        except Exception as e:
            return self._errorReturn(e)

    # Get set of attributes for given log entry
    def get_attributes_for_log_entry(self, event_id):
        client_cert = self.requestCertificate()
        method = 'get_attributes_for_log_entry'
        try:
            results = \
                self._delegate.get_attributes_for_log_entry(client_cert, \
                                                                event_id)
            return results
        except Exception as e:
            return self._errorReturn(e)

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
    def log_event(self, client_cert, message, attributes, user_id):
        method = 'log_event'
        args = {'user_id' : user_id, 'message' : message, 'attributes' : attributes}
        chapi_log_invocation(LOG_LOG_PREFIX, method, [], {}, args)
        session = self.db.getSession()
        now = datetime.utcnow()
        # Record the event
        # Insert into logging_entry (event_time, user_id, message) values
        # (now, user_id, message)
        ins = self.db.LOGGING_ENTRY_TABLE.insert().values(event_time=str(now), user_id=str(user_id), message=message)
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
        session.commit()
        session.close()
        chapi_log_result(LOG_LOG_PREFIX, method, True)
        return self._successReturn(True)

    def get_log_entries_by_author(self, client_cert, user_id, num_hours):
        method = 'get_log_entries_by_author'
        args = {'user_id' : user_id, 'num_hours' : num_hours}
        chapi_log_invocation(LOG_LOG_PREFIX, method, [], {}, args)
        session = self.db.getSession()
        q = session.query(self.db.LOGGING_ENTRY_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.user_id == user_id)
        min_event_time = datetime.utcnow() - relativedelta(hours=num_hours)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.event_time >= min_event_time)
        rows = q.all()
        session.close()
        entries = [construct_result_row(row, self.columns, 
                                        self.field_mapping) for row in rows]
        chapi_log_result(LOG_LOG_PREFIX, method, entries)
        return self._successReturn(entries)

    def get_log_entries_for_context(self, client_cert, context_type, context_id, num_hours):
        method = 'get_log_entries_for_context'
        args = {'context_type' : context_type, 'context_id' : context_id, 
                'num_hours' : num_hours}
        chapi_log_invocation(LOG_LOG_PREFIX, method, [], {}, args)
        session = self.db.getSession()
        q = session.query(self.db.LOGGING_ENTRY_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.id == self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.event_id)
        min_event_time = datetime.utcnow() - relativedelta(hours=num_hours)
        q = q.filter(self.db.LOGGING_ENTRY_TABLE.c.event_time >= min_event_time)
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_name == context_type_names[context_type])
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.attribute_value == context_id)
        rows = q.all()
        session.close()
        entries = [construct_result_row(row, self.columns, 
                                        self.field_mapping) for row in rows]
        chapi_log_result(LOG_LOG_PREFIX, method, entries)
        return self._successReturn(entries)

    def get_log_entries_by_attributes(self, client_cert, attribute_sets, num_hours):
        method = 'get_log_entries_by_attributes'
        args = {'attribute_sets' : attribute_sets, 'num_hours' : num_hours}
        chapi_log_invocation(LOG_LOG_PREFIX, method, [], {}, args)
        session = self.db.getSession()
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
        session.close()
        entries = [construct_result_row(row, self.columns, 
                                        self.field_mapping) for row in rows]
        chapi_log_result(LOG_LOG_PREFIX, method, entries)
        return self._successReturn(entries)


    def get_attributes_for_log_entry(self, client_cert, event_id):
        method = 'get_attributes_for_log_entry'
        args = {'event_id' : event_id}
        chapi_log_invocation(LOG_LOG_PREFIX, method, [], {}, args)
        session = self.db.getSession()
        q = session.query(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE)
        q = q.filter(self.db.LOGGING_ENTRY_ATTRIBUTE_TABLE.c.event_id == event_id)
        rows = q.all()
        session.close()
        entries = [construct_result_row(row, self.attribute_columns, 
                                        self.attribute_field_mapping) for row in rows]
        chapi_log_result(LOG_LOG_PREFIX, method, entries)
        return self._successReturn(entries)



