#----------------------------------------------------------------------         
# Copyright (c) 2011-2015 Raytheon BBN Technologies
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

# Implementation of the Member Authority

from datetime import datetime
from dateutil.relativedelta import relativedelta
import logging
import os
import re
import subprocess
import tempfile
import uuid
from collections import defaultdict

from sqlalchemy.orm import mapper
import sqlalchemy

import amsoil.core.pluginmanager as pm

from gcf.geni.util.urn_util import URN
import gcf.sfa.trust.gid as sfa_gid
import gcf.sfa.trust.certificate as cert
import gcf.geni.util.cred_util as cred_util

import tools.MA_constants as MA
from tools.dbutils import *
from tools.cert_utils import *
from tools.chapi_log import *
from tools.guard_utils import *
from tools.chapi_utils import *
from tools.ABACManager import *
from tools.mapped_tables import *
from chapi.MemberAuthority import MAv1DelegateBase
from chapi.Exceptions import *
import chapi.Parameters

# classes for mapping to sql tables

class OutsideCert(object):
    pass

class InsideKey(object):
    pass

class SshKey(object):
    pass

def derive_username(email_address, session):
    # See http://www.linuxjournal.com/article/9585
    # try to figure out a reasonable username.
    # php: $email_addr = filter_var($email_address, FILTER_SANITIZE_EMAIL);
    email_addr = re.sub('[^a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^_`\{\|\}~@\.\[\]]', '', email_address)
    # print "<br/>derive2: email_addr = $email_addr<br/>\n"; */

    # Now get the username portion.
    atindex = email_addr.rindex('@')
    # print "atindex = $atindex<br/>\n"; */
    username = email_addr[0:atindex]
    # print "base username = $username<br/>\n"; */

    # Follow the rules here:
    #         http://groups.geni.net/geni/wiki/GeniApiIdentifiers#Name
    #  * Max 8 characters
    #  * Case insensitive internally
    #  * Obey this regex: '^[a-zA-Z][\w]\{0,7\}$'
    # Additionally, sanitize the username so it can be used in ABAC

    # lowercase the username
    username = username.lower()
    # remove unacceptable characters
    username = re.sub('[^a-z0-9_]', '', username)
    # remove leading non-alphabetic chars
    username = re.sub('^[^a-z]*', '', username)
    # trim the username to 8 chars
    if len(username)>8:
        username = username[0:8]

    if not username:
        username = "geni1"

    if not username_exists(username, session):
        # print "no conflict with $username<br/>\n";
        return username
    else:
        # shorten the name and append a two-digit number
        if len(username)>6:
            username = username[0:6]
        for i in range(1, 100):
            if i<10:
                tmpname = username+'0'+str(i)
            else:
                tmpname = username+str(i)
            # print "trying $tmpname<br/>\n";
            if not username_exists(tmpname, session):
                # print "no conflict with $tmpname<br/>\n";
                return tmpname

    raise CHAPIv1ArgumentError('Unable to find a username based on '+email_address)

def username_exists(name, session):
    q = session.query(MemberAttribute.member_id)
    q = q.filter(MemberAttribute.name == 'username')
    q = q.filter(MemberAttribute.value == name)
    rows = q.all()
    return len(rows) > 0

def make_member_urn(cert, username):
    ma_urn = get_urn_from_cert(cert)
    ma_authority, ma_type, ma_name = parse_urn(ma_urn)
    return make_urn(ma_authority, 'user', username)

def parse_urn(urn):
    '''returns authority, type, name'''
    m = re.search('urn:publicid:IDN\+([^\+]+)\+([^\+]+)\+([^\+]+)$', urn)
    if m is not None:
        return m.group(1), m.group(2), m.group(3)
    else:
        return None

def make_urn(authority, typ, name):
    return 'urn:publicid:IDN+'+authority+'+'+typ+'+'+name

class MAv1Implementation(MAv1DelegateBase):
    
    def __init__(self):
        super(MAv1Implementation, self).__init__()
        self.db = pm.getService('chdbengine')
        self.config = pm.getService('config')
        self._sa_handler = pm.getService('sav1handler')
        mapper(MemberAttribute, self.db.MEMBER_ATTRIBUTE_TABLE)
        mapper(OutsideCert, self.db.OUTSIDE_CERT_TABLE)
        mapper(InsideKey, self.db.INSIDE_KEY_TABLE)
        mapper(SshKey, self.db.SSH_KEY_TABLE)
        self.table_mapping = {
            "_GENI_MEMBER_SSL_CERTIFICATE": OutsideCert,
            "_GENI_MEMBER_SSL_EXPIRATION": OutsideCert,
            "_GENI_MEMBER_SSL_PRIVATE_KEY": OutsideCert,
            "_GENI_MEMBER_INSIDE_CERTIFICATE": InsideKey,
            "_GENI_MEMBER_INSIDE_PRIVATE_KEY": InsideKey
            }
        self.cert = self.config.get('chapi.ma_cert')
        self.key = self.config.get('chapi.ma_key')
        self.urn = get_urn_from_cert(open(self.cert).read())

        self.portal_admin_email = self.config.get('chapi.portal_admin_email')
        self.portal_help_email = self.config.get('chapi.portal_help_email')
        self.ch_from_email = self.config.get('chapi.ch_from_email')
        self.server = self.config.get('chrm.authority')

        trusted_root = self.config.get('chapiv1rpc.ch_cert_root')
        self.trusted_roots = [os.path.join(trusted_root, f) \
            for f in os.listdir(trusted_root) if not f.startswith('CAT')]

        self.logging_service = pm.getService('loggingv1handler')
        # FIXME: Parametrize path to these certs
        # init for ClientAuth
        self.kmcert = '/usr/share/geni-ch/km/km-cert.pem'
        self.kmkey = '/usr/share/geni-ch/km/km-key.pem'


    # This call is unprotected: no checking of credentials
    def get_version(self, session):
        method = 'get_version'

        all_optional_fields = dict(MA.optional_fields.items() + \
                                   MA.optional_key_fields.items())
        import flask
        api_versions = \
            {chapi.Parameters.VERSION_NUMBER : flask.request.url_root}
        implementation_info = get_implementation_info(MA_LOG_PREFIX)
        version_info = {"VERSION": chapi.Parameters.VERSION_NUMBER,
                        "URN " : self.urn,
                        "IMPLEMENTATION" : implementation_info,
                        "SERVICES" : MA.services,
                        "CREDENTIAL_TYPES": MA.credential_types,
                        "API_VERSIONS" : api_versions,
                        "FIELDS": all_optional_fields}
        result =  self._successReturn(version_info)

        return result

    # ensure that all of a set of entries are attributes
    def check_attributes(self, attrs):
        for attr in attrs:
            if attr not in MA.attributes:
                raise CHAPIv1ArgumentError('Unknown attribute ' + attr)

    # filter out all the users that have a particular value of an attribute
    def get_uids_for_attribute(self, session, attr, value):
        if attr == 'MEMBER_UID':  # If we already have the UID, return it
            if isinstance(value, list):
                return value
            else:
                return [value]
        q = session.query(MemberAttribute.member_id)
        q = q.filter(MemberAttribute.name == MA.field_mapping[attr])

        if attr=="MEMBER_EMAIL":
            if isinstance(value, types.ListType):
                if len(value) == 0:
                    # Do you mean any? (no additional filter)? Or no rows?
                    q = q.filter(MemberAttribute.value == None)
                else:
                    q = q.filter(func.lower(MemberAttribute.value).in_(value))
            else:
                q = q.filter(func.lower(MemberAttribute.value) == value)
        elif isinstance(value, types.ListType):
            if len(value) == 0:
                # FIXME: If you specify an empty list, what should the behavior be?
                # Do you mean any value? Or only a value of None? Or only rows with no entry for this value?
                # Is this right?
                q = q.filter(MemberAttribute.value == None)
#                chapi_debug(MA_LOG_PREFIX, "get_uids_for_attrs got empty list for VALUE: ATTR = %s, MAP = %s, VALUE = %s" % \
#                                (attr, MA.field_mapping[attr], value))
            else:
                q = q.filter(MemberAttribute.value.in_(value))
        else:
            q = q.filter(MemberAttribute.value == value)

#        chapi_debug(MA_LOG_PREFIX, "get_uids_for_attrs: ATTR = %s, MAP = %s, VALUE = %s" % \
#                       (attr, MA.field_mapping[attr], value))
#        chapi_debug(MA_LOG_PREFIX, "get_uids_for_attrs: ATTR = %s, MAP = %s, VALUE = %s, Q = %s" % \
#                       (attr, MA.field_mapping[attr], value, q))
        rows = q.all()
        return [row.member_id for row in rows]

    # find the value of an attribute for a given user
    def get_attr_for_uid(self, session, attr, uid):
        q = session.query(MemberAttribute.value)
        if MA.field_mapping.has_key(attr):
            q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
        else:
            q = q.filter(MemberAttribute.name == attr)
        q = q.filter(MemberAttribute.member_id == uid)
        rows = q.all()
        return [row.value for row in rows]

    # find the value for a column in a table
    def get_val_for_uid(self, session, table, field, uid):
        if hasattr(field, '__call__'):
            q = session.query(table)
        else:
            q = session.query(getattr(table, field))
        q = q.filter(table.member_id == uid)
        rows = q.all()
        result = []
        for row in rows:
            if hasattr(field, '__call__'):
                value = field(row)
            else:
                value = getattr(row, field)
            result.append(value)
        return result

    # construct a list of ssh keys
    def get_ssh_keys_for_uid(self, session, uid, include_private):
        q = session.query(self.db.SSH_KEY_TABLE)
        q = q.filter(self.db.SSH_KEY_TABLE.c.member_id == uid)
        rows = q.all()
        excluded = ['id', 'member_id'] + [['private_key'], []][include_private]
        ret = [{} for i in range(len(rows))]
        for i, row in enumerate(rows):
            for key in set(row.keys()) - set(excluded):
                ret[i][key] = getattr(row, key)
        return ret

    def transform_for_result(self, val):
        """Transform values to be returned as results to client. Datatypes
        requiring transformation from internal representation to
        external represnetation should be modified here.

        """
        # datetimes get returned as strings
        if isinstance(val, datetime.datetime):
            return val.strftime(STANDARD_DATETIME_FORMAT)
        else:
            # No other transformation so just return it
            return val


    # Common code for answering query
    def lookup_member_info(self, options, allowed_fields, session):
        """Look up a set of fields about a set of members.

        Return a dictionary whose top-level keys are the URNS of
        members whose information has been retrieved. The top-level
        values are dictionaries whose keys are field names and whose
        values are the data elements extracted from the database.

        """
        # preliminaries
        (selected_columns,
         match_criteria) = unpack_query_options(options, MA.field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a valid "match" option')
        self.check_attributes(match_criteria)
        selected_columns = set(selected_columns) & set(allowed_fields)

        # first, get all the member ids of matches
        uids = [set(self.get_uids_for_attribute(session, attr, value))
                for attr, value in match_criteria.iteritems()]
        uids = set.intersection(*uids)
        #chapi_info(MA_LOG_PREFIX,
        #            "UIDS = %s COLS = %s CRIT = %s" % (uids,
        #                                               selected_columns,
        #                                               match_criteria))

        # Bucket the requested columns so we can make efficient use of
        # the database
        uid_cols = ["MEMBER_UID", "_GENI_IDENTIFYING_MEMBER_UID",
                    "_GENI_PRIVATE_MEMBER_UID"]
        table_cols = defaultdict(set)
        for col in selected_columns:
            if col in uid_cols:
                table_cols['uid'].add(col)
            elif col in self.table_mapping:
                table_cols[self.table_mapping[col]].add(col)
            else:
                table_cols[MemberAttribute].add(col)
        #for x in table_cols:
        #    chapi_info(MA_LOG_PREFIX,
        #                "Get columns %r from table %s" % (table_cols[x], x))

        # Store the results in a dictionary of dictionaries
        uid_result = defaultdict(dict)

        # MemberAttribute -- always fetch these because it will
        # include the URN which is required for keying the result.
        self._lookup_member_attributes(session, uids,
                                       table_cols[MemberAttribute], uid_result)
        # InsideKey
        if InsideKey in table_cols:
            self._lookup_inside_key_info(session, uids, table_cols[InsideKey],
                                         uid_result)
        # OutsideCert
        if OutsideCert in table_cols:
            self._lookup_outside_cert_info(session, uids,
                                           table_cols[OutsideCert], uid_result)
        # Add requested UID columns with UID value
        if 'uid' in table_cols:
            for uid in uids:
                inner = uid_result[uid]
                for field in table_cols['uid']:
                    inner[field] = uid

        # Post-process the results to key them by URN instead of UID
        result = dict()
        for uid in uid_result:
            if 'MEMBER_URN' not in uid_result[uid]:
                # Is this a problem? Probably not, but better safe
                # than sorry.  It might indicate erroneous queries by
                # a client or erroneous result sets from
                # sub-functions. Warn and move on.
                msg = 'No MEMBER_URN for %s in lookup_member_info.'
                chapi_warn(MA_LOG_PREFIX, msg % (uid))
                continue
            urn = uid_result[uid]['MEMBER_URN']
            result[urn] = uid_result[uid]
            # Clean up: if MEMBER_URN was not part of the original
            # request, remove it from the result. It was added for
            # keying the result.
            if 'MEMBER_URN' not in selected_columns:
                del result[urn]['MEMBER_URN']
        return self._successReturn(result)

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, client_cert, 
                                  credentials, options, session):
        result = self.lookup_member_info(options, MA.public_fields, session)
        return result

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, 
                                   options, session):
        result = self.lookup_member_info(options, MA.private_fields, session)
        return result

    # This call is protected: Only authorities can call it
    def lookup_public_identifying_member_info(self, client_cert,
                                              credentials, options, session):
        result = \
            self.lookup_member_info(options, 
                                    MA.public_fields + MA.identifying_fields, 
                                    session)
        return result

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options, session):
        result = self.lookup_member_info(options, MA.identifying_fields, session)
        return result

    # This is a generic lookup_member_info call
    # You get all the info you are allowed to see
    # All public (for anyone)
    # Identifying (for those allowed by policy)
    # Private (only for you)
    def lookup_allowed_member_info(self, client_cert, credentials, options, session):

        # 0. Segregate the fields into public, private and identifying fields
        (public_fields, identifying_fields, private_fields) = \
            self.segregate_member_fields(options)
#        chapi_info("LAMI", "PUB = %s ID = %s PRIV = %s" % \
#                       (public_fields, identifying_fields, private_fields))

        # 1. Get Public for everyone with public fields
        public_options = {'match' : options['match'], 'filter' : public_fields}
        public_result = \
            self.lookup_public_member_info(client_cert, credentials,\
                                               public_options, session)
        chapi_debug(MA_LOG_PREFIX, "PUB = %s" % public_result)

        ma_handler = pm.getService('mav1handler')
        ma_guard = ma_handler.getGuard()
#        chapi_info(MA_LOG_PREFIX, "MA_GUARD = %s" % ma_guard)

        # 2. If I am  asking for identifying fields (or no fields listed)
        #       accumulate a list of members for whom the guard says
        #       I can call lookup_identifying_member_info
        allowed_identifying_match = \
            self.determine_allowed_match(client_cert, credentials, ma_guard, \
                                             'lookup_identifying_member_info', \
                                             options, {}, session)

        # 2b. Call lookup_identifying_member_info with identifyable members 
        #   with identifying fields
        identifying_options = {'match' : allowed_identifying_match, \
                                   'filter' : identifying_fields}
        identifying_result = \
            self.lookup_identifying_member_info(client_cert, credentials,\
                                                    identifying_options, session)
        chapi_debug(MA_LOG_PREFIX, "ID = %s" % identifying_result)


        # 3. If I am asking for private fields (or no fields listed)
        #       accumulate a list of members for whom the guard says
        #       I can call lookup_private_member_info
        allowed_private_match = \
            self.determine_allowed_match(client_cert, credentials, ma_guard, \
                                             'lookup_private_member_info', \
                                             options, {}, session)

        # 3b. Make the call to lookup_private_member_info with private members
        #    with private fields
        private_options = {'match' : allowed_private_match, 'filter' : private_fields}
        private_result = \
            self.lookup_private_member_info(client_cert, credentials,\
                                                private_options, session)
        chapi_debug(MA_LOG_PREFIX, "PRIV = %s" % private_result)

        # 4. Merge these three results together
        aggregate_result = {}
        for urn in public_result['value'].keys():
            aggregate_result[urn] = {}
            for field, value in public_result['value'][urn].items():
                aggregate_result[urn][field] = value
            if urn in identifying_result['value']:
                for field, value in identifying_result['value'][urn].items():
                    aggregate_result[urn][field] = value
            if urn in private_result['value']:
                for field, value in private_result['value'][urn].items():
                    aggregate_result[urn][field] = value
        result = self._successReturn(aggregate_result)
        return result

    def segregate_member_fields(self, options):
        public_fields = []
        identifying_fields = []
        private_fields = []
        if 'filter' not in options:
            public_fields = MA.public_fields
            identifying_fields = MA.identifying_fields
            private_fields = MA.private_fields
        else:
            fields = options['filter']
            for field in fields:
                if field in MA.public_fields:
                    public_fields.append(field)
                elif field in MA.identifying_fields:
                    identifying_fields.append(field)
                elif field in MA.private_fields:
                    private_fields.append(field)
                else:
                    raise CHAPIv1ArgumentError("Unknown member field %s" % field)
        return public_fields, identifying_fields, private_fields
                
    def determine_allowed_match(self, client_cert, credentials, \
                                    ma_guard, method, options, \
                                    arguments, session):
        invocation_check = ma_guard.get_invocation_check(method)
#        chapi_info("DAM", "IC = %s" % invocation_check)
        subjects = invocation_check.validate_arguments(client_cert, method, \
                                                           credentials, \
                                                           options, arguments, session)
#        chapi_info("DAM", "SUBJECTS = %s" % subjects)
        if len(subjects) == 0:
            return {}

        subject_type = subjects.keys()[0]
        subject_ids = subjects[subject_type]
#        chapi_info("DAM", "SUBJECT_TYPE = %s" % subject_type)
#        chapi_info("DAM", "SUBJECT_IDS = %s" % subject_ids)

        allowed_users = []
        for subject_id in subject_ids:
            try:
                individual_subject = {subject_type : [subject_id]}
                invocation_check.authorize_call(client_cert, method, \
                                                    credentials, options,\
                                                    arguments, individual_subject, \
                                                    session)
                allowed_users.append(subject_id)
#                chapi_info("DAM", "Allowing member %s for method %s" % (subject_id, method))
            except Exception as e:
#                chapi_info("DAM", "E = %s" % e)
#                chapi_info("DAM", "Not allowing member %s for method %s" % (subject_id, method))
                pass

        allowed_match =  {subject_type :  allowed_users}
 #       chapi_info("DAM", "ALLOWED_MATCH = %s" % allowed_match)
        return allowed_match

    # Called only by authorities
    # Retieve requested private, public, identifying info by EPPN
    def lookup_login_info(self, client_cert, jcredentials, options, session):
        result = self.lookup_member_info(options,
                                         MA.public_fields + MA.identifying_fields + MA.private_fields,
                                         session)
        return result


    # This call is protected
    def update_member_info(self, client_cert, member_urn, 
                           credentials, options, session):
        # determine whether self_asserted
        try:
            gid = sfa_gid.GID(string = client_cert)
            self_asserted = ['f', 't'][gid.get_urn() == member_urn]
        except:
            self_asserted = 'f'

        # find member to update
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        uid = uids[0]
        
        # do the update
        all_keys = {}
        for attr, value in options['fields'].iteritems():
            if attr in MA.attributes:
                self.update_attr(session, attr, value, uid, self_asserted)
            elif attr in self.table_mapping:
                table = self.table_mapping[attr]
                if table not in all_keys:
                    all_keys[table] = {}
                all_keys[table][MA.field_mapping[attr]] = value
        for table, keys in all_keys.iteritems():
            self.update_keys(session, table, keys, uid)
            
        result = self._successReturn(True)
        return result

    # update or insert value of attribute attr for user uid
    def update_attr(self, session, attr, value, uid, self_asserted):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            q = session.query(MemberAttribute)
            if MA.field_mapping.has_key(attr):
                q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
            else:
                q = q.filter(MemberAttribute.name == attr)
            q = q.filter(MemberAttribute.member_id == uid)
            q.update({"value": value})
        else:
            if MA.field_mapping.has_key(attr):
                obj = MemberAttribute(MA.field_mapping[attr], value, \
                                          uid, self_asserted)
            else:
                obj = MemberAttribute(attr, value, \
                                          uid, self_asserted)
            session.add(obj)

    # delete attribute row if it is there
    def delete_attr(self, session, attr, uid, value=None):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            q = session.query(MemberAttribute)
            if MA.field_mapping.has_key(attr):
                q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
            else:
                q = q.filter(MemberAttribute.name == attr)
            q = q.filter(MemberAttribute.member_id == uid)
            if value is not None:
                q = q.filter(MemberAttribute.value == value)
            q.delete()


    # update or insert into one of the two SSL key tables
    def update_keys(self, session, table, keys, uid):
        if self.get_val_for_uid(session, table, "certificate", uid):
            q = session.query(table)
            q = q.filter(getattr(table, "member_id") == uid)
            q.update(keys)
        else:
            if "certificate" not in keys:
                raise CHAPIv1ArgumentError('Cannot insert just private key - missing certificate')
            obj = table()
            obj.member_id = uid
            for key, val in keys.iteritems():
                 setattr(obj, key, val)
            session.add(obj)

    # delete all existing ssh keys, and replace them with specified ones
    def update_ssh_keys(self, session, keys, uid):
        q = session.query(SshKey)
        q = q.filter(SshKey.member_id == uid)
        q.delete()
        for key in keys:
            obj = SshKey()
            obj.member_id = uid
            for col, val in key.iteritems():
                setattr(obj, col, val)
            session.add(obj)

    # part of the API, mainly call get_all_credentials()
    def get_credentials(self, client_cert, member_urn, 
                        credentials, options, session):

        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        uid = uids[0]
        creds = self.get_all_credentials(session, uid, client_cert)

        return self._successReturn(creds)

    # Construct a list of credentials in AM format
    # [{'geni_type' : type, 'geni_version' : version, 'geni_value' : value}]
    # where type is SFA for a UserCredential or ABAC for ABAC credentials
    def get_all_credentials(self, session, uid, client_cert):
        creds = []
        sfa_raw_creds = [self.get_user_credential(session, uid, client_cert)]
        abac_assertions = []
        user_urn = convert_member_uid_to_urn(uid, session)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: outside certs = '+str(certs))
        certs = self.get_val_for_uid(session, OutsideCert, "certificate", uid)
        if not certs:
            certs = self.get_val_for_uid(session, InsideKey, "certificate", 
                                         uid)
        if not certs:
            chapi_warn(MA_LOG_PREFIX, "Get Credentials found no cert for uid %s" % uid, {'user': get_email_from_cert(client_cert)})
            return creds

        user_cert = certs[0]

        abac_raw_creds = []
        if lookup_operator_privilege(user_urn, session):
           assertion = generate_abac_credential("ME.IS_OPERATOR<-CALLER",
                                                self.cert, self.key, {"CALLER" : user_cert})
           abac_raw_creds.append(assertion)
        if lookup_pi_privilege(user_urn, session):
            assertion = generate_abac_credential("ME.IS_PI<-CALLER",
                                                 self.cert, self.key, {"CALLER" : user_cert})
            abac_raw_creds.append(assertion)
        sfa_creds = \
            [{'geni_type' : 'geni_sfa', 'geni_version' : '3', 'geni_value' : cred}
             for cred in sfa_raw_creds if cred is not None]
        abac_creds = \
            [{'geni_type' : 'geni_abac', 'geni_version' : '1', 'geni_value' : cred}
             for cred in abac_raw_creds]
        creds = sfa_creds + abac_creds
        return creds


    # build a user credential based on the user's cert
    def get_user_credential(self, session, uid, client_cert):
        # append the MA cert to the client_cert to make a proper chain
        ma_cert = None
        with open(self.cert, 'r') as f:
            ma_cert = f.read()
        chain_cert = client_cert + ma_cert
        gid = sfa_gid.GID(string=chain_cert)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: gid = '+str(gid))
        expires = datetime.datetime.utcnow() + relativedelta(years=MA.USER_CRED_LIFE_YEARS)
        cred = cred_util.create_credential(gid, gid, expires, "user", \
                  self.key, self.cert, self.trusted_roots)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: cred = '+cred.save_to_string())
        return cred.save_to_string()

    def create_member(self, client_cert, attributes, 
                      credentials, options, session):

        user_email = get_email_from_cert(client_cert)

        # if it weren't for needing to track which attributes were self-asserted
        # we could just use options['fields']

        # rearrange the attributes a bit
        atmap = dict()
        for attr in attributes:
            atmap[attr['name']]=attr  # also value, self_asserted

        # check to make sure that there's an email address
        if 'email_address' not in atmap.keys():
            raise CHAPIv1DatabaseError("Missing required email_address attribute")
        else:
            email_address = atmap['email_address']['value']

        # username
        user_name = derive_username(email_address, session)
        user_urn = make_member_urn(client_cert, user_name)

        atmap['username'] = {'name':'username', 'value':user_name, 'self_asserted':False}
        atmap['urn'] = {'name':'urn', 'value':user_urn, 'self_asserted':False}

        member_id = uuid.uuid4()

        ins = self.db.MEMBER_TABLE.insert().values({'member_id':str(member_id)})
        result = session.execute(ins)
        for attr in atmap.values():
            attr['member_id'] = str(member_id)
            ins = self.db.MEMBER_ATTRIBUTE_TABLE.insert().values(attr)
            session.execute(ins)

        # Log the successful creation of member
        msg = "Activated GENI user : %s (%s)" % (self._get_displayname_for_member_urn(user_urn, session), user_urn)
        attrs = {"MEMBER" : str(member_id)}
        log_options = self.subcall_options(options)
        self.logging_service.log_event(msg, attrs, credentials, log_options,
                                       session=session)
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})
        # Send email to portal admins
        msgbody = "There is a new account registered on %s:\n" % self.server
        msgbody += "\nmember_id: %s" %member_id
        for key in atmap.keys():
            msgbody += "\n%s: %s" %  (key, atmap[key]['value'])

        tolist = [unicode(self.portal_admin_email)]
        subject = "New GENI CH account registered"
        send_email(tolist, unicode(self.ch_from_email), unicode(self.portal_help_email),subject,msgbody)

        result = self._successReturn(atmap.values())

        return result

    # Implementation of KEY Service methods

    def create_key(self, client_cert, credentials, options, session):
        
        user_email = get_email_from_cert(client_cert)

       # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No 'fields' in create_key")
        fields = options['fields']
        validate_fields(fields, MA.required_create_key_fields, \
                            MA.allowed_create_key_fields)
        member_urn = fields['KEY_MEMBER']
        del fields['KEY_MEMBER']
        create_fields = \
            convert_dict_to_internal(fields, MA.key_field_mapping)

        # Add member_id to create_fields
        lookup_member_id_options = {'match' : {'MEMBER_URN' : member_urn},
                                    'filter' : ['MEMBER_UID']}
        result = \
            self.lookup_public_member_info(client_cert, credentials, 
                                           lookup_member_id_options,
                                           session)
        if result['code'] != NO_ERROR:
            return result # Shouldn't happen: Should raise exception instead

        member_id = result['value'][member_urn]['MEMBER_UID']
        create_fields['member_id'] = member_id

        ins = self.db.SSH_KEY_TABLE.insert().values(create_fields)
        result = session.execute(ins)
        key_id = str(result.inserted_primary_key[0])
        fields["KEY_ID"] = key_id
        fields["KEY_MEMBER"] = member_urn


        # Log the creation of the SSH key
        client_uuid = get_uuid_from_cert(client_cert)
        attrs = {"MEMBER" : client_uuid}
        log_options = self.subcall_options(options)
        msg = "%s registering SSH key %s" % (self._get_displayname_for_member_urn(member_urn, session), key_id)
        self.logging_service.log_event(msg, attrs, credentials, log_options,
                                       session=session)
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(fields)
        return result

    def delete_key(self, client_cert, key_id, \
                       credentials, options, session):


        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
        num_del = q.delete()
        if num_del == 0:
            raise CHAPIv1DatabaseError("No key with id %s to delete" % key_id)

        # Log the deletion of the SSH key
        client_uuid = get_uuid_from_cert(client_cert)
        member_urn = convert_member_uid_to_urn(client_uuid, session)
        attrs = {"MEMBER" : client_uuid}
        msg = "%s deleting SSH key %s" % (self._get_displayname_for_member_urn(member_urn, session), key_id)
        log_options = self.subcall_options(options)
        self.logging_service.log_event(msg, attrs, credentials, log_options,
                                       session=session)

        result = self._successReturn(True)

        return result

    def update_key(self, client_cert, key_id, \
                       credentials, options, session):

        # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No 'fields' in update_key")
        fields = options['fields']
        validate_fields(fields, None, MA.updatable_key_fields)
        update_fields = \
            convert_dict_to_internal(fields, MA.key_field_mapping)
        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
#        print "UPDATE_FIELDS = " + str(update_fields)
        num_upd = q.update(update_fields)

        if num_upd == 0:
            raise CHAPIv1DatabaseError("No key with id %s to update" % key_id)

        result = self._successReturn(True)

        return result

    def lookup_keys(self, client_cert, credentials, options, session):

        selected_columns, match_criteria = \
            unpack_query_options(options, MA.key_field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a valid "match" option')
        self.check_attributes(match_criteria)

        q = session.query(self.db.SSH_KEY_TABLE, \
                              self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id, \
                              self.db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self.db.SSH_KEY_TABLE.c.member_id == self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name=='urn')

        # Handle key_member specially: it is not part of the SSH key table
        if 'KEY_MEMBER' in match_criteria.keys():
            member_urns = match_criteria['KEY_MEMBER']
            if not isinstance(member_urns, types.ListType): 
                    member_urns = [member_urns]
            if len(member_urns) == 0:
                # FIXME: If you specify an empty list, what should the behavior be?
                # ANSWER: This is fine. An empty list means 
                # 'give me keys for no users' hence ' give me no keys'
                q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == None)
                #  chapi_debug(MA_LOG_PREFIX, "lookup_keys had empty list of urns")
            else:
                q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value.in_(member_urns))
                enabled, disabled = check_disabled_users(self.db, member_urns, session)
                member_urns = enabled
                if len(disabled) > 0:
                    chapi_info(MA_LOG_PREFIX, 
                               "Attempt to access SSH keys of disabled users %s" % 
                               disabled)
            del match_criteria['KEY_MEMBER']

        q = add_filters(q, match_criteria, self.db.SSH_KEY_TABLE, 
                        MA.key_field_mapping, session)
        rows = q.all()

        keys = {}
        for row in rows:
            member_urn = row.value
            member_uid = row.member_id
            if member_urn not in keys:
                keys[member_urn] = []

            # Do not return any SSH key info for disabled users
            if not self.is_enabled(member_uid, session):
                continue

            keys[member_urn].append(construct_result_row(row, \
                         selected_columns, MA.key_field_mapping, session))
            # Per federation API, the KEY ID must be exported as a string
            for key_data in keys[member_urn]:
                if 'KEY_ID' in key_data:
                    key_id = key_data['KEY_ID']
                    key_data['KEY_ID'] = str(key_id)


        # Strip out any KEY_PRIVATE fields from key returns not for the 
        # calling user
        member_urn = get_urn_from_cert(client_cert)
        for urn, all_key_fields in keys.items():
#            chapi_info(MA_LOG_PREFIX, "URN = %s FIELDS = %s" % (urn, all_key_fields))
            if urn != member_urn:
                for key_fields in all_key_fields:
                    if 'KEY_PRIVATE' in key_fields:
                        del key_fields['KEY_PRIVATE']

        result = self._successReturn(keys)

        return result

    def _make_csr(self, member_urn, member_id, session):
        """Create a certifcate signing request. If the given member has a
        private key in the outside cert table, use it. Otherwise
        generate a new private key along with the csr.

        Return a tuple of (private_key, csr_file).

        """
        q = session.query(OutsideCert.private_key)
        q = q.filter(OutsideCert.member_id == member_id)
        rows = q.all()
        if len(rows) > 0 and rows[0].private_key:
            chapi_info(MA_LOG_PREFIX,
                       "Reusing private key for member %s" % (member_urn))
            return make_csr_from_key(rows[0].private_key)
        else:
            chapi_info(MA_LOG_PREFIX,
                       "Creating new private key for member %s" % (member_urn))
            return make_csr()

    def _store_outside_cert(self, session, member_id, certificate, expiration,
                            private_key):
        """Store cert and key in outside_cert table. If an entry exists,
        update the row, otherwise insert a new row.

        Return True on success, raises an exception on failure.
        """
        # Query for a row. If one exists, update it in the db. If no
        # result found, insert a new row.
        q = session.query(OutsideCert)
        q = q.filter(OutsideCert.member_id == member_id)
        try:
            row = q.one()
            # Found one row, update it with new info.
            values = dict(certificate=certificate,
                          expiration=expiration,
                          private_key=private_key)
            # Returns row count on success, raises exception on error
            q.update(values)
            msg = 'Updated certificate for %s' % (member_id)
            chapi_info(MA_LOG_PREFIX, msg)
            return True
        except sqlalchemy.orm.exc.NoResultFound:
            # Insert a new row
            insert_fields = dict(certificate=certificate,
                                 member_id=member_id,
                                 expiration=expiration)
            if private_key:
                insert_fields['private_key'] = private_key
            ins = self.db.OUTSIDE_CERT_TABLE.insert().values(insert_fields)
            # Nothing useful returned on insert, raises exception on error.
            session.execute(ins)
            msg = 'Inserted new certificate for %s' % (member_id)
            chapi_info(MA_LOG_PREFIX, msg)
            return True
        except sqlalchemy.orm.exc.MultipleResultsFound:
            # Inconsistent database!
            msg = ('Multiple rows found for member_id %s'
                   + ' in outside certificate table.')
            raise Exception(msg % (member_id))

    # Member certificate methods
    def create_certificate(self, client_cert, member_urn, 
                           credentials, options, session):

        user_email = get_email_from_cert(client_cert)

        # Lookup UID and email from URN
        match = {'MEMBER_URN' : member_urn}
        lookup_options = {'match' : match}
        lookup_response = self.lookup_member_info(lookup_options,
                                                  ['MEMBER_EMAIL',
                                                   'MEMBER_UID'], session)
        member_info = lookup_response['value'][member_urn]
        member_email = str(member_info['MEMBER_EMAIL'])
        member_id = str(member_info['MEMBER_UID'])

        # Grab the CSR or make CSR/KEY
        if 'csr' in options:
            # CSR provided: Generate cert but no private key
            private_key = None
            csr_data = options['csr']
            (csr_fd, csr_file) = tempfile.mkstemp()
            os.close(csr_fd)
            open(csr_file, 'w').write(csr_data)
        else:
            # No CSR provided: Generate cert and private key
            private_key, csr_file = self._make_csr(member_urn, member_id,
                                                   session)

        cert_pem = make_cert(member_id, member_email, member_urn,
                             self.cert, self.key, csr_file)

        os.unlink(csr_file)

        expiration = get_expiration_from_cert(cert_pem)

        # Grab signer pem
        signer_pem = open(self.cert).read()

        # This is the aggregate cert
        # Need to return it somehow
        cert_chain = cert_pem + signer_pem

        store_result = self._store_outside_cert(session, member_id, cert_chain,
                                                expiration, private_key)
        result = self._successReturn(True)

        # chapi_audit call
        msg = "Created certificate for %s" % member_urn
        if private_key:
            msg = msg + " with private key"
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        return result

    ### ClientAuth

    # Dictionary of client_name => client_urn
    def list_clients(self, client_cert, session):

        q = session.query(self.db.MA_CLIENT_TABLE)
        rows = q.all()
        entries = {}
        for row in rows:
            entries[row.client_name] = row.client_urn
        result = self._successReturn(entries)

        return result

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id, session):

        q = session.query(self.db.INSIDE_KEY_TABLE.c.client_urn)
        q = q.filter(self.db.INSIDE_KEY_TABLE.c.member_id == member_id)
        rows = q.all()
        entries = [str(row.client_urn) for row in rows]
        result = self._successReturn(entries)

        return result

    # Authorize/deauthorize a tool with respect to a user
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense, session):

        member_urn = convert_member_uid_to_urn(member_id, session)
        user_email = get_email_from_cert(client_cert)

        #chapi_audit(MA_LOG_PREFIX, "Called authorize_client "+member_id+' '+client_urn)
        if authorize_sense:
            private_key, csr_file = make_csr()
            member_email = convert_member_uid_to_email(member_id, session)
            cert_pem = make_cert(member_id, member_email, member_urn, \
                                     self.cert, self.key, csr_file)
            os.unlink(csr_file)
            expiration = get_expiration_from_cert(cert_pem)
            signer_pem = open(self.cert).read()
            cert_chain = cert_pem + signer_pem

            # insert into MA_INSIDE_KEY_TABLENAME
            # (member_id, client_urn, certificate, private_key)
            # values 
            # (member_id, client_urn, cert, key)
            insert_values = {'client_urn' : client_urn,
                             'member_id' : str(member_id),
                             'private_key' : private_key,
                             'certificate' : cert_chain,
                             'expiration' : expiration}
            ins = self.db.INSIDE_KEY_TABLE.insert().values(insert_values)
            session.execute(ins)

            # log_event
            msg = "Authorizing client %s for member %s" % (client_urn, self._get_displayname_for_member_urn(member_urn, session))
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, [], {},
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        else:
            # delete from MA_INSIDE_KEY_TABLENAME
            # where member_id = member_id and client_urn = client_urn
            q = session.query(InsideKey)
            q = q.filter(InsideKey.member_id == member_id)
            q = q.filter(InsideKey.client_urn == client_urn)
            q = q.delete()

            # log_event
            msg = "Deauthorizing client %s for member %s" % (client_urn, self._get_displayname_for_member_urn(member_urn, session))
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, [], {},
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(True)
        return result

    def mail_enable_user(self, msg, subject):
        msgbody = msg + " on " + self.config.get("chrm.authority")
        tolist = [unicode(self.portal_admin_email)]
        send_email(tolist, unicode(self.ch_from_email), unicode(self.portal_admin_email),subject,msgbody)

    def is_enabled(self, member_id, session):
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_id).\
            filter(MemberAttribute.name == MA.field_mapping['_GENI_MEMBER_ENABLED'])
        rows = q.all()

        return (len(rows)==0 or rows[0][0] == 'y')

    # enable/disable a user/member  (private)
    def enable_user(self, client_cert, member_urn, enable_sense, 
                    credentials, options, session):
        '''Mark a member/user as enabled or disabled.
        IFF enabled_sense is True, then user is unconditionally enabled, otherwise disabled.
        returns the previous sense.'''

        user_email = get_email_from_cert(client_cert)
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+str(enable_sense))

        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_id = uids[0]

        # find the old value
        was_enabled = self.is_enabled(member_id, session)

        # set the new value
        enabled_str = 'y' if enable_sense else 'n'
        did_something = False
        if (not was_enabled and enable_sense) or (was_enabled and not enable_sense):
            did_something = True
            self.update_attr(session, '_GENI_MEMBER_ENABLED', enabled_str, member_id, 'f')


        if did_something:
            # log_event
            msg = "Set member %s status to %s" % \
                (member_urn, 'enabled' if enable_sense else 'disabled')
            attribs = {"MEMBER" : member_id}
            log_options = self.subcall_options(options)
            self.logging_service.log_event(msg, attribs, credentials, log_options,
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})
            self.mail_enable_user(user_email + " " + msg, ("Enabled CH user" if enable_sense else "Disabled CH user"))
        else:
            chapi_info(MA_LOG_PREFIX, "Member %s already %s" % (member_urn, 'enabled' if enable_sense else 'disabled'), {'user': user_email})

        result = self._successReturn(was_enabled)

        return result

    def check_user_enabled(self, client_cert, session):
        client_urn = get_urn_from_cert(client_cert)
        client_email = get_email_from_cert(client_cert)
        user_email = client_email
        client_uuid = get_uuid_from_cert(client_cert)
        client_name = get_name_from_urn(client_urn)

        is_enabled = self.is_enabled(client_uuid, session)

        if is_enabled:
#            chapi_debug(MA_LOG_PREFIX, "CUE: user '%s' (%s) enabled" % (client_name, client_urn))
            pass
        else:
            chapi_audit_and_log(MA_LOG_PREFIX, "CUE: user '%s' (%s) disabled" % (client_name, client_urn), logging.INFO, {'user': user_email})
            raise CHAPIv1AuthorizationError("User %s (%s) disabled" % (client_name, client_urn));

    # send email about new lead/operator privilege
    def mail_new_privilege(self,member_id, privilege, session):
        options = {'match' : {'MEMBER_UID' : member_id },'filter': ['_GENI_MEMBER_DISPLAYNAME','MEMBER_FIRSTNAME','MEMBER_LASTNAME','MEMBER_EMAIL']}  
        info = self.lookup_member_info(options, MA.identifying_fields, session)
        member_info = info['value']
        pretty_name = ""
        member_email = None
        if len(member_info) > 0:
            for row in member_info:
                pretty_name = get_member_display_name(member_info[row],row)
                member_email = '"%s" <%s>' % (pretty_name, member_info[row]['MEMBER_EMAIL'])
        msgbody = "Dear " + pretty_name + ",\n\n"
        subject = ""
        if privilege == "PROJECT_LEAD":
            subject = "You are now a GENI Project Lead" 
            msgbody += "Congratulations, you have been made a 'Project Lead', meaning you can create GENI"
            msgbody += " Projects, as well as create slices in projects and reserve resources.\n\n"

            msgbody += "If you are using the GENI Portal, see "
            msgbody += "http://groups.geni.net/geni/wiki/SignMeUp#a2b.CreateaGENIProject "  #FIXME: Edit if page moves
            msgbody += "for instructions on creating a project.\n\n"
        else:
            subject = "You are now a GENI Operator" 
            msgbody += "You are now a GENI Operator on "
            msgbody += self.config.get("chrm.authority") + ".\n\n"
        
        msgbody += "Sincerely,\n"
        msgbody += "GENI Clearinghouse operations\n"

        tolist = [member_email]
        cclist = [unicode(self.portal_admin_email)]
        send_email(tolist, unicode(self.ch_from_email),unicode(self.portal_help_email),subject,msgbody,cclist)

    #  member_privilege (private)
    def add_member_privilege(self, client_cert, member_uid, privilege, 
                             credentials, options, session):
        '''Mark a member/user as having a particular contextless privilege.
        privilege must be either OPERATOR or PROJECT_LEAD.'''


        user_email = get_email_from_cert(client_cert)
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_uid+' '+privilege)

        if not (privilege in ['OPERATOR', 'PROJECT_LEAD']):
            raise CHAPIv1ArgumentError('Privilege %s undefined' % (privilege))

        # find the old value
        # Technically we should use the MA.field_mapping, but we know
        # the privilege is one of two strings that map to themselves.
        # If there are ever other privilege strings you can use here that do
        # not map to themselves, fix this query.
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == privilege)
        rows = q.all()

        if len(rows)==0:
            was_enabled = False
        else:
            was_enabled = (rows[0][0] == 'true')

        if not was_enabled:
            self.update_attr(session, privilege, 'true', member_uid, 'f')

            # log_event
            msg = "Granted member %s privilege %s" %  (self._get_displayname_for_member_id(member_uid, session), privilege)
            attribs = {"MEMBER" : member_uid}
            log_options = self.subcall_options(options)
            self.logging_service.log_event(msg, attribs, credentials, log_options,
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

            # Email admins, new project lead/operator
            self.mail_new_privilege(member_uid,privilege, session)

        result = self._successReturn(not was_enabled)

        return result

    def revoke_member_privilege(self, client_cert, member_uid, 
                                privilege, credentials, options, session):
        '''Mark a member/user as not having a particular contextless privilege.
        privilege must be either OPERATOR or PROJECT_LEAD.'''

        user_email = get_email_from_cert(client_cert)
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_uid+' '+privilege)

        if not (privilege in ['OPERATOR', 'PROJECT_LEAD']):
            raise CHAPIv1ArgumentError('Privilege %s undefined' % (privilege))

        # find the old value
        # Technically we should use the MA.field_mapping, but we know
        # the privilege is one of two strings that map to themselves.
        # If there are ever other privilege strings you can use here that do
        # not map to themselves, fix this query.
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == privilege)
        rows = q.all()

        if len(rows)==0:
            was_enabled = False
        else:
            was_enabled = (rows[0][0] == 'true')

        if was_enabled:
            # if revoking lead privilege, first check if member is lead on any projects
            # if yes, look for an admin with lead authorization and make him/her lead on the project
            # if there isn't an authorized admin, don't revoke lead privilege
            if privilege=="PROJECT_LEAD":
                row = self.get_attr_for_uid(session,"MEMBER_URN",member_uid)
                member_urn = row[0]
                #get projects for which member is lead

                projects = self._sa_handler._delegate.lookup_projects_for_member(client_cert, member_urn, 
                                                                                 credentials, {}, session)

                for project in projects['value']:
                    new_lead_urn = None
                    if project['PROJECT_ROLE'] == 'LEAD':
                        project_urn = project['PROJECT_URN']
                        #look for authorized admin to be new lead
                        members = self._sa_handler._delegate.lookup_project_members(client_cert, project_urn, 
                                                                                    credentials, {}, session)
                        for member in members['value']:
                            if member['PROJECT_ROLE'] == 'ADMIN':
                                q = session.query(MemberAttribute.value).\
                                    filter(MemberAttribute.member_id == member['PROJECT_MEMBER_UID']).\
                                    filter(MemberAttribute.name == 'PROJECT_LEAD')
                                rows = q.all()
                                if rows[0][0] == 'true':
                                    row = self.get_attr_for_uid(session,"MEMBER_URN",member['PROJECT_MEMBER_UID'])
                                    new_lead_urn = row[0]
                                    
                                    options = {'members_to_change':[{'PROJECT_MEMBER': member_urn,'PROJECT_ROLE':'MEMBER'}, \
                                                                        {'PROJECT_MEMBER': new_lead_urn,'PROJECT_ROLE':'LEAD'}]}
                                    result = self._sa_handler._delegate.modify_project_membership(client_cert, project['PROJECT_URN'], credentials, options, session)
                                    break
                        if new_lead_urn == None:
                            msg = ('Cannot revoke lead privilege from %s.'
                                   + ' No authorized admin to take lead role'
                                   + ' on project %s')
                            msg = msg % (member_urn, project_urn)
                            raise CHAPIv1ArgumentError(msg)
        if was_enabled:
            self.delete_attr(session, privilege, member_uid)

            # log_event
            msg = "Revoking member %s privilege %s" %  (self._get_displayname_for_member_id(member_uid, session), privilege)
            attribs = {"MEMBER" : member_uid}
            log_options = self.subcall_options(options)
            self.logging_service.log_event(msg, attribs, credentials, log_options,
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(was_enabled)

        return result

    # Do not allow add/remove attribute to modify certain attribute names
    def valid_attr(self, attr):
        if attr is None or attr.isspace():
            return False
#        core_attrs = ['PROJECT_LEAD', 'OPERATOR', 'eppn', 'urn',
#        'username', 'first_name', 'last_name', 'affiliation',
#        'displayName', 'email_address', 'reference', 'member_enabled']
        core_attrs = ['PROJECT_LEAD', 'OPERATOR', 'eppn', 'urn',
                      'username', 'email_address', 'member_enabled']
        if attr.strip() in core_attrs:
            return False
        return True

    #  add member_attribute (private)
    def add_member_attribute(self, client_cert, member_urn, attr_name, attr_value, 
                             attr_self_assert,
                             credentials, options, session):
        user_email = get_email_from_cert(client_cert)
        caller_uid = get_uuid_from_cert(client_cert)
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+attr_name+' = '+attr_value)

        if not self.valid_attr(attr_name):
            raise CHAPIv1ArgumentError('%s not a valid member attribute' % attr_name)
        attr_name = attr_name.strip()

        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_uid = uids[0]

        # If the caller is the member whose attribute is being acted
        # on then mark this self_asserted regardless of what they said
        if attr_self_assert == 'f' and member_uid == caller_uid:
            # Unless they are an operator
            q2 = session.query(MemberAttribute.value).\
                filter(MemberAttribute.member_id == member_uid).\
                filter(MemberAttribute.name == "OPERATOR").\
                filter(MemberAttribute.value == "true")
            is_op = q2.count() > 0
            if not is_op:
                chapi_warn(MA_LOG_PREFIX, "Caller tried to add own attribute %s and say it was not self asserted" % attr_name, {'user': user_email})
                attr_self_assert = 't'

        # Map the requested attribute from the API attribute name to the internal (db) name,
        # if necessary.
        db_name = attr_name
        if MA.field_mapping.has_key(attr_name):
            db_name = MA.field_mapping[attr_name]

        # find the old value
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == db_name)
        rows = q.all()

        was_defined = (len(rows)>0)
        old_value = None
        if was_defined:
            old_value = rows[0][0]
            if old_value != attr_value:
                was_defined = False

        if not was_defined:
            self.update_attr(session, attr_name, attr_value, member_uid, attr_self_assert)

        if not was_defined:
            # log_event
            # Here we use the mapped value of the attribute name. Not all caps looks nicer.
            msg = "Set member %s attribute %s to %s" %  (self._get_displayname_for_member_urn(member_urn, session), db_name, attr_value )
            attribs = {"MEMBER" : member_uid}
            log_options = self.subcall_options(options)
            self.logging_service.log_event(msg, attribs, credentials, log_options,
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})
        result = self._successReturn(old_value)

        return result

    def remove_member_attribute(self, client_cert, member_urn, attr_name, 
                                credentials, options, session, attr_value=None):
        user_email = get_email_from_cert(client_cert)
        caller_urn = get_urn_from_cert(client_cert)
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+attr_name)

        if not self.valid_attr(attr_name):
            raise CHAPIv1ArgumentError('%s not a valid member attribute' % attr_name)
        attr_name = attr_name.strip()

        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_uid = uids[0]

        # Map the requested attribute from the API attribute name to the internal (db) name,
        # if necessary.
        db_name = attr_name
        if MA.field_mapping.has_key(attr_name):
            db_name = MA.field_mapping[attr_name]

        # find the old value
        q = session.query(MemberAttribute.value, MemberAttribute.self_asserted).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == db_name)
        if attr_value is not None:
            q = q.filter(MemberAttribute.value == attr_value)
        rows = q.all()

        was_defined = (len(rows)>0)

#        chapi_debug(MA_LOG_PREFIX, 'RMA.ROWS = %s' % rows, {'user': user_email})

        old_value = None
        do_remove = True
        if was_defined:
            old_value = rows[0][0]
            was_self = rows[0][1]
            if member_urn == caller_urn:
                if not was_self:
                    # If the person is an operator, fine. Otherwise,
                    # bail
                    q2 = session.query(MemberAttribute.value).\
                        filter(MemberAttribute.member_id == member_uid).\
                        filter(MemberAttribute.name == "OPERATOR").\
                        filter(MemberAttribute.value == "true")
                    is_op = q2.count() > 0
                    if not is_op:
                        chapi_info(MA_LOG_PREFIX, "User %s tried to remove own non self-asserted attribute %s" % (member_urn,
                                                                                                                  db_name), {'user': user_email})
                        do_remove = False
            if do_remove:
                self.delete_attr(session, attr_name, member_uid, attr_value)

        # log_event
        if was_defined and do_remove:
            # Here we use the mapped value of the attribute name. Not all caps looks nicer.
            msg = "Removed member %s attribute %s" %  (self._get_displayname_for_member_urn(member_urn, session), db_name)
            if attr_value is not None:
                msg = msg + "=%s" % attr_value
            attribs = {"MEMBER" : member_uid}
            log_options = self.subcall_options(options)
            self.logging_service.log_event(msg, attribs, credentials, log_options,
                                           session=session)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        if do_remove:
            result = self._successReturn(old_value)
        else:
            result = {'code': AUTHORIZATION_ERROR, 'value': old_value,
                      'output': "Cannot remove own non self-asserted attribute"}
        return result

    def _get_displayname_for_member_id(self, member_id, session):
        member_urn = convert_member_uid_to_urn(member_id, session)
        return self._get_displayname_for_member_urn(member_urn, session)

    def _get_displayname_for_member_urn(self, member_urn, session):
        urns = []
        urns.append(member_urn)
        options = {\
            "match" : {"MEMBER_URN" : urns}, 
            "filter" : ["_GENI_MEMBER_DISPLAYNAME", "MEMBER_FIRSTNAME", 
                        "MEMBER_LASTNAME", "MEMBER_EMAIL"]}
        result = self.lookup_member_info(options, MA.identifying_fields, 
                                         session)
        if result['code'] != NO_ERROR or member_urn not in result['value']:
            return member_urn
        else:
            return get_member_display_name(result['value'][member_urn], member_urn)

    def _lookup_member_attributes(self, session, m_ids, fields, result):
        """Look up the fields for the given member ids in the
        ma_member_attributes table. Put the fields in result, keyed by
        member id, then field.

        """
        # A utility function to leverage list comprehension
        def field2db_name(field):
            if field in MA.field_mapping:
                return MA.field_mapping[field]
            else:
                return field

        if m_ids is None or (isinstance(m_ids, types.ListType) and len(m_ids) == 0):
            return result

        # Always include the MEMBER_URN, we need it for the result
        if 'MEMBER_URN' not in fields:
            fields.add('MEMBER_URN')
        db_names = set([field2db_name(x) for x in fields])
        q = session.query(MemberAttribute.member_id, MemberAttribute.name,
                          MemberAttribute.value)
        q = q.filter(MemberAttribute.member_id.in_(m_ids))
        q = q.filter(MemberAttribute.name.in_(db_names))
        maRows = q.all()

        # Build a temporary structure for the data. Top level keys are
        # the member ids and top level values are dictionaries. The
        # value dictionaries are keyed by db_names and contain the
        # values from the db.
        tmp_result = defaultdict(dict)
        for row in maRows:
            #chapi_info(MA_LOG_PREFIX, "M_A Row: %r" % (row,))
            tmp_result[row.member_id][row.name] = row.value

        # Set the member_enabled flag to 'True' if there is no entry in table
        for member_id, attrs in tmp_result.items():
            if 'member_enabled' not in attrs: attrs['member_enabled'] = True
            attrs['member_enabled'] = (attrs['member_enabled'] != 'n')

        # Now build the result structure using field names instead of
        # db_names for the keys of the inner dictionaries.
        for uid in m_ids:
            db_fields = tmp_result[uid]
            uid_fields = result[uid]
            for field in fields:
                db_name = field2db_name(field)
                if db_name in db_fields:
                    val = db_fields[db_name]
                    uid_fields[field] = self.transform_for_result(val)
                else:
                    uid_fields[field] = None
        return result

    def _lookup_inside_key_info(self, session, m_ids, fields, result):
        """Look up the fields for the given member ids in the InsideKey
        table. Put the fields in result, keyed by member id, then
        field.

        """
        # Filter requested fields to only those for which a mapping
        # exists. No mapping, no info.
        fields = [f for f in fields if f in MA.field_mapping]

        # If no members or no fields (after filtering), do nothing
        if not m_ids or not fields or (isinstance(m_ids, types.ListType) and len(m_ids) == 0):
            return result

        # Always fetch expiration to renew expiring certificates
        columns = set([InsideKey.member_id, InsideKey.expiration])
        for f in fields:
            columns.add(getattr(InsideKey, MA.field_mapping[f]))

        # Convert the set columns into a list for SQLAlchemy
        q = session.query(*columns)
        q = q.filter(InsideKey.member_id.in_(m_ids))
        rows = q.all()
        for row in rows:
            for f in fields:
                val = getattr(row, MA.field_mapping[f])
                result[row.member_id][f] = self.transform_for_result(val)
            # And check for expiration on each row...
            dt = row.expiration - datetime.datetime.utcnow()
            if dt.days < 14:
                chapi_info(MA_LOG_PREFIX,
                           "Renewing inside cert for %s" % (row.member_id))
                # call renew
                private_key = getattr(row, 'private_key', None)
                self._renew_inside_cert(session, row.member_id, private_key)
        return result

    def _renew_inside_cert(self, session, member_id, private_key):
        """Renew the inside certificate of the given member."""
        if not private_key:
            # private key is not available, get it from the DB
            q = session.query(InsideKey.private_key)
            q = q.filter(InsideKey.member_id == member_id)
            row = q.one()
            private_key = row.private_key
        (pk, csr_file) = make_csr_from_key(private_key)
        q = session.query(MemberAttribute.name, MemberAttribute.value)
        q = q.filter(MemberAttribute.member_id == member_id)
        q = q.filter(MemberAttribute.name.in_(['email_address', 'urn']))
        rows = q.all()
        meminfo = dict()
        for row in rows:
            meminfo[row.name] = row.value
        cert_pem = make_cert(member_id, meminfo['email_address'],
                             meminfo['urn'], self.cert, self.key, csr_file)
        expiration = get_expiration_from_cert(cert_pem)
        # Grab signer pem
        signer_pem = open(self.cert).read()
        # This is the certificate chain
        cert_chain = cert_pem + signer_pem
        store_result = self._store_renewed_inside_cert(session, member_id,
                                                       cert_chain, expiration,
                                                       private_key)

    def _store_renewed_inside_cert(self, session, member_id, certificate,
                                   expiration, private_key):
        """Store cert and key in inside_key table. If an entry exists, update
        the row, otherwise error because we don't have enough info to
        do otherwise. Inside certificates have a tool associated with
        them (client_urn), but that's not known in the thread that
        calls this method.

        Return True on success, raises an exception on failure.

        """
        # Query for a row. If one exists, update it in the db. If no
        # result found, insert a new row.
        q = session.query(InsideKey)
        q = q.filter(InsideKey.member_id == member_id)
        try:
            row = q.one()
            # Found one row, update it with new info.
            values = dict(certificate=certificate,
                          expiration=expiration)
            # Returns row count on success, raises exception on error
            updated = q.update(values)
            # Must explicitly commit here because we're run as part of
            # a read-only method so no autocommit happens
            session.commit()
            msg = 'Updated inside certificate for %s' % (member_id)
            chapi_info(MA_LOG_PREFIX, msg)
            return True
        except sqlalchemy.orm.exc.NoResultFound:
            # How did we get here?
            msg = ('No row found for member_id %s'
                   + ' in inside certificate table on renewal.'
                   + ' Please notify portal-help@geni.net')
            raise Exception(msg % (member_id))
        except sqlalchemy.orm.exc.MultipleResultsFound:
            # Inconsistent database!
            msg = ('Multiple rows found for member_id %s'
                   + ' in inside certificate table. Please'
                   + ' notify portal-help@geni.net')
            raise Exception(msg % (member_id))

    def _lookup_outside_cert_info(self, session, m_ids, fields, result):
        """Look up the fields for the given member ids in the OutsideCert
        table. Put the fields in result, keyed by member id, then
        field.

        """
        # Filter requested fields to only those for which a mapping
        # exists. No mapping, no info.
        fields = [f for f in fields if f in MA.field_mapping]

        # If no members or no fields (after filtering), do nothing
        if not m_ids or not fields or (isinstance(m_ids, types.ListType) and len(m_ids) == 0):
            return result

        columns = set([OutsideCert.member_id])
        for f in fields:
            columns.add(getattr(OutsideCert, MA.field_mapping[f]))

        q = session.query(*columns)
        q = q.filter(OutsideCert.member_id.in_(m_ids))
        rows = q.all()
        for row in rows:
            for f in fields:
                val = getattr(row, MA.field_mapping[f])
                result[row.member_id][f] = self.transform_for_result(val)
        return result
