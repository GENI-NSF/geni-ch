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

# Implementation of the Member Authority

from datetime import datetime
from dateutil.relativedelta import relativedelta
import logging
import os
import re
import subprocess
import tempfile
import uuid

from sqlalchemy.orm import mapper

import amsoil.core.pluginmanager as pm

from geni.util.urn_util import URN
import sfa.trust.gid as sfa_gid
import sfa.trust.certificate as cert
import geni.util.cred_util as cred_util

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

def row_cert_to_public_key(row):
    raw_certificate = row.certificate
    cert_obj = cert.Certificate(string=raw_certificate)
    public_key = cert_obj.get_pubkey()
    return public_key.get_pubkey_string()

MA.field_mapping["_GENI_MEMBER_SSL_PUBLIC_KEY"] = row_cert_to_public_key
MA.field_mapping["_GENI_MEMBER_INSIDE_PUBLIC_KEY"] = row_cert_to_public_key


def derive_username(email_address):
    # See http://www.linuxjournal.com/article/9585
    # try to figure out a reasonable username.
    # php: $email_addr = filter_var($email_address, FILTER_SANITIZE_EMAIL);
    email_addr = re.sub('[^a-zA-Z0-9!#$%&\'*+\-/=?^_`{|}~@.[]]', '', email_address)
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
    # trim the username to 8 chars
    if len(username)>8:
        username = username[0:8]
    # remove unacceptable characters
    username = re.sub('![a-z0-9_]', '', username)
    # remove leading non-alphabetic leading chars
    username = re.sub('^[^a-z]*', '', username)

    if not username:
        username = "geni1"

    if not username_exists(username):
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
            if not username_exists(tmpname):
                # print "no conflict with $tmpname<br/>\n";
                return tmpname

    raise CHAPIv1ArgumentError('Unable to find a username based on '+email_address)

def username_exists(name):
    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(MemberAttribute.member_id)
    q = q.filter(MemberAttribute.name == 'username')
    q = q.filter(MemberAttribute.value == name)
    rows = q.all()
    session.close()
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
            "_GENI_MEMBER_SSL_PUBLIC_KEY": OutsideCert,
            "_GENI_MEMBER_SSL_PRIVATE_KEY": OutsideCert,
            "_GENI_MEMBER_INSIDE_CERTIFICATE": InsideKey,
            "_GENI_MEMBER_INSIDE_PUBLIC_KEY": InsideKey,
            "_GENI_MEMBER_INSIDE_PRIVATE_KEY": InsideKey
            }
        self.cert = self.config.get('chapi.ma_cert')
        self.key = self.config.get('chapi.ma_key')

        self.portal_admin_email = self.config.get('chapi.portal_admin_email')
        self.portal_help_email = self.config.get('chapi.portal_help_email')
        self.ch_from_email = self.config.get('chapi.ch_from_email')

        trusted_root = self.config.get('chapiv1rpc.ch_cert_root')
        self.trusted_roots = [os.path.join(trusted_root, f) \
            for f in os.listdir(trusted_root) if not f.startswith('CAT')]

        self.logging_service = pm.getService('loggingv1handler')
        # init for ClientAuth
        self.kmcert = '/usr/share/geni-ch/km/km-cert.pem'
        self.kmkey = '/usr/share/geni-ch/km/km-key.pem'


    # This call is unprotected: no checking of credentials
    def get_version(self):
        method = 'get_version'
#        user_email = get_email_from_cert(self.requestCertificate())
#        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, {}, {'user': user_email})
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, {})

        all_optional_fields = dict(MA.optional_fields.items() + \
                                   MA.optional_key_fields.items())
        version_info = {"VERSION": chapi.Parameters.VERSION_NUMBER,
                        "CREDENTIAL_TYPES": MA.credential_types,
                        "OBJECTS" : MA.objects,
                        "SERVICES" : MA.services,
                        "FIELDS": all_optional_fields}
        result =  self._successReturn(version_info)

#        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        chapi_log_result(MA_LOG_PREFIX, method, result)
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
        if isinstance(value, types.ListType):
            q = q.filter(MemberAttribute.value.in_(value))
        else:
            q = q.filter(MemberAttribute.value == value)

        chapi_debug(MA_LOG_PREFIX, "get_uids_for_attrs: ATTR = %s, MAP = %s, VALUE = %s" % \
                       (attr, MA.field_mapping[attr], value))
#        chapi_debug(MA_LOG_PREFIX, "get_uids_for_attrs: ATTR = %s, MAP = %s, VALUE = %s, Q = %s" % \
#                       (attr, MA.field_mapping[attr], value, q))
        rows = q.all()
        return [row.member_id for row in rows]

    # find the value of an attribute for a given user
    def get_attr_for_uid(self, session, attr, uid):
        q = session.query(MemberAttribute.value)
        q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
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

    # Common code for answering query
    def lookup_member_info(self, options, allowed_fields):
        
        # preliminaries
        selected_columns, match_criteria = \
            unpack_query_options(options, MA.field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a "match" option')
        self.check_attributes(match_criteria)
        selected_columns = set(selected_columns) & set(allowed_fields)
        session = self.db.getSession()

        # first, get all the member ids of matches
        uids = [set(self.get_uids_for_attribute(session, attr, value)) \
                for attr, value in match_criteria.iteritems()]
        uids = set.intersection(*uids)

        chapi_debug(MA_LOG_PREFIX, "UIDS = %s COLS = %s CRIT = %s" % (uids, selected_columns, match_criteria))

        # then, get the values
        members = {}
        for uid in uids:
            row = self.get_attr_for_uid(session,"MEMBER_URN",uid)
            if row is None or len(row) == 0:
                chapi_info(MA_LOG_PREFIX, "lookup_member_info: no member_urn row from get_attr_for_uid %s (the MA?)" % uid)
                continue
            urn = row[0]
            values = {}
            for col in selected_columns:
                if col in ["MEMBER_UID", "_GENI_IDENTIFYING_MEMBER_UID"]:
                    values[col] = uid
                else:
                    vals = None
                    if col in MA.attributes:
                        vals = self.get_attr_for_uid(session, col, uid)
                    elif col in self.table_mapping:
                        vals = self.get_val_for_uid(session, \
                            self.table_mapping[col], MA.field_mapping[col], uid)
                    if vals:
                        values[col] = vals[0]
                    elif 'filter' in options:
                        values[col] = None
            members[urn] = values

        session.close()
        return self._successReturn(members)

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, client_cert, credentials, options):
        method = 'lookup_public_member_info'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        result = self.lookup_member_info(options, MA.public_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        method = 'lookup_private_member_info'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        result = self.lookup_member_info(options, MA.private_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        method = 'lookup_identifying_member_info'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        result = self.lookup_member_info(options, MA.identifying_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
        method = 'update_member_info'
        args = {'member_urn' : member_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        # determine whether self_asserted
        try:
            gid = sfa_gid.GID(string = client_cert)
            self_asserted = ['f', 't'][gid.get_urn() == member_urn]
        except:
            self_asserted = 'f'

        # find member to update
        session = self.db.getSession()
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            session.close()
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
            
        session.close()

        result = self._successReturn(True)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # update or insert value of attribute attr for user uid
    def update_attr(self, session, attr, value, uid, self_asserted):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            q = session.query(MemberAttribute)
            q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
            q = q.filter(MemberAttribute.member_id == uid)
            q.update({"value": value})
        else:
            obj = MemberAttribute(MA.field_mapping[attr], value, \
                                  uid, self_asserted)
            session.add(obj)
        session.commit()

    # delete attribute row if it is there
    def delete_attr(self, session, attr, uid):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            q = session.query(MemberAttribute)
            q = q.filter(MemberAttribute.name == MA.field_mapping[attr])
            q = q.filter(MemberAttribute.member_id == uid)
            q.delete()
        session.commit()

    # update or insert into one of the two SSL key tables
    def update_keys(self, session, table, keys, uid):
        if self.get_val_for_uid(session, table, "certificate", uid):
            q = session.query(table)
            q = q.filter(getattr(table, "member_id") == uid)
            q.update(keys)
        else:
            if "certificate" not in keys:
                session.close()
                raise CHAPIv1ArgumentError('Cannot insert just private key')
            obj = table()
            obj.member_id = uid
            for key, val in keys.iteritems():
                 setattr(obj, key, val)
            session.add(obj)
        session.commit()

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
        session.commit()

    # part of the API, mainly call get_all_credentials()
    def get_credentials(self, client_cert, member_urn, credentials, options):
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, 'get_credentials', credentials,
                             options, {'member_urn' : member_urn}, {'user': user_email})
        session = self.db.getSession()

        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            session.close()
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        uid = uids[0]
        creds = self.get_all_credentials(session, uid, client_cert)

        session.close()
        chapi_log_result(MA_LOG_PREFIX, 'get_credentials', creds, {'user': user_email})
        return self._successReturn(creds)

    # Construct a list of credentials in AM format
    # [{'geni_type' : type, 'geni_version' : version, 'geni_value' : value}]
    # where type is SFA for a UserCredential or ABAC for ABAC credentials
    def get_all_credentials(self, session, uid, client_cert):
        creds = []
        sfa_raw_creds = [self.get_user_credential(session, uid, client_cert)]
        abac_assertions = []
        user_urn = convert_member_uid_to_urn(uid)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: outside certs = '+str(certs))
        certs = self.get_val_for_uid(session, OutsideCert, "certificate", uid)
        if not certs:
            certs = self.get_val_for_uid(session, InsideKey, "certificate", 
                                         uid)
        if not certs:
            return creds

        user_cert = certs[0]

        abac_raw_creds = []
        if lookup_operator_privilege(user_urn):
           assertion = generate_abac_credential("ME.IS_OPERATOR<-CALLER",
                                                self.cert, self.key, {"CALLER" : user_cert})
           abac_raw_creds.append(assertion)
        if lookup_pi_privilege(user_urn):
            assertion = generate_abac_credential("ME.IS_PI<-CALLER",
                                                 self.cert, self.key, {"CALLER" : user_cert})
            abac_raw_creds.append(assertion)
        sfa_creds = \
            [{'geni_type' : 'geni_sfa', 'geni_version' : 1, 'geni_value' : cred} 
             for cred in sfa_raw_creds]
        abac_creds = \
            [{'geni_type' : 'geni_abac', 'geni_version' : 1, 'geni_value' : cred} 
             for cred in abac_raw_creds]
        creds = sfa_creds + abac_creds
        return creds


    # build a user credential based on the user's cert
    def get_user_credential(self, session, uid, client_cert):
        user_email = get_email_from_cert(client_cert)
        cred_cert = None
        certs = self.get_val_for_uid(session, OutsideCert, "certificate", uid)
        for cert in certs:
            if cert.startswith(client_cert):
                chapi_debug(MA_LOG_PREFIX, 'found client in outside certs', {'user': user_email})
                cred_cert = cert
                break
        if not cred_cert:
            certs = self.get_val_for_uid(session, InsideKey, "certificate", uid)
            for cert in certs:
                if cert.startswith(client_cert):
                    chapi_debug(MA_LOG_PREFIX, 'found client in inside certs', {'user': user_email})
                    cred_cert = cert
                    break
        if not cred_cert:
            chapi_warn(MA_LOG_PREFIX,
                       'get_user_credential did not find a matching certificate',
                       {'user': user_email})
            return None

        gid = sfa_gid.GID(string=cred_cert)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: gid = '+str(gid))
        expires = datetime.utcnow() + relativedelta(years=1)
        cred = cred_util.create_credential(gid, gid, expires, "user", \
                  self.key, self.cert, self.trusted_roots)
        #chapi_debug(MA_LOG_PREFIX, 'GUC: cred = '+cred.save_to_string())
        return cred.save_to_string()

    def create_member(self, client_cert, attributes, credentials, options):

        method = 'create_member'
        args = {'attributes' : attributes}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        # if it weren't for needing to track which attributes were self-asserted
        # we could just use options['fields']

        # rearrange the attributes a bit
        atmap = dict()
        for attr in attributes:
            atmap[attr['name']]=attr  # also value, self_asserted

        # check to make sure that there's an email address
        if 'email_address' not in atmap.keys():
            raise CHAPIv1DatabaseError("No email_address attribute")
        else:
            email_address = atmap['email_address']['value']

        # username
        user_name = derive_username(email_address)
        user_urn = make_member_urn(client_cert, user_name)

        atmap['username'] = {'name':'username', 'value':user_name, 'self_asserted':False}
        atmap['urn'] = {'name':'urn', 'value':user_urn, 'self_asserted':False}

        member_id = uuid.uuid4()

        session = self.db.getSession()
        ins = self.db.MEMBER_TABLE.insert().values({'member_id':str(member_id)})
        result = session.execute(ins)
        for attr in atmap.values():
            attr['member_id'] = str(member_id)
            ins = self.db.MEMBER_ATTRIBUTE_TABLE.insert().values(attr)
            session.execute(ins)
        session.commit()
        session.close()

        # Log the successful creation of member
        #self.logging_service = pm.getService('loggingv1handler')
        msg = "Activated GENI user : %s (%s)" % (self._get_displayname_for_member_urn(user_urn), user_urn)
        attrs = {"MEMBER" : member_id}
        self.logging_service.log_event(msg, attrs, member_id)
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})
        # FIXME: Send email to portal admins

        result = self._successReturn(atmap.values())

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # Implementation of KEY Service methods

    def create_key(self, client_cert, credentials, options):
        
        method = 'create_key'
        args = {}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

       # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No fields in create_key")
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
            self.lookup_public_member_info(client_cert, credentials, \
                                               lookup_member_id_options)
        if result['code'] != NO_ERROR:
            return result # Shouldn't happen: Should raise exception instead

        member_id = result['value'][member_urn]['MEMBER_UID']
        create_fields['member_id'] = member_id

        session = self.db.getSession()
        ins = self.db.SSH_KEY_TABLE.insert().values(create_fields)
        result = session.execute(ins)
        key_id = str(result.inserted_primary_key[0])
        fields["KEY_ID"] = key_id
        fields["KEY_MEMBER"] = member_urn

        session.commit()
        session.close()

        # Log the creation of the SSH key
        client_uuid = get_uuid_from_cert(client_cert)
        attrs = {"MEMBER" : client_uuid}
        msg = "%s registered SSH key %s" % (self._get_displayname_for_member_urn(member_urn), key_id)
        self.logging_service.log_event(msg, attrs, client_uuid)
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(fields)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def delete_key(self, client_cert, member_urn, key_id, \
                       credentials, options):

        method = 'delete_key'
        args = {'member_urn' : member_urn, 'key_id' : key_id}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        session = self.db.getSession()
        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
        num_del = q.delete()
        if num_del == 0:
            session.close()
            raise CHAPIv1DatabaseError("No key with id  %s" % key_id)
        session.commit()
        session.close()

        # Log the deletion of the SSH key
        client_uuid = get_uuid_from_cert(client_cert)
        attrs = {"MEMBER" : client_uuid}
        msg = "%s deleted SSH key %s" % (self._get_displayname_for_member_urn(member_urn), key_id)
        self.logging_service.log_event(msg, attrs, client_uuid)

        result = self._successReturn(True)
        
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def update_key(self, client_cert, member_urn, key_id, \
                       credentials, options):

        method = 'update_key'
        args = {'member_urn' : member_urn, 'key_id' : key_id}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No fields in update_key")
        fields = options['fields']
        validate_fields(fields, None, MA.updatable_key_fields)
        update_fields = \
            convert_dict_to_internal(fields, MA.key_field_mapping)
        session = self.db.getSession()
        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
#        print "UPDATE_FIELDS = " + str(update_fields)
        num_upd = q.update(update_fields)

        if num_upd == 0:
            session.close()
            raise CHAPIv1DatabaseError("No key with id %s" % key_id)
        session.commit()
        session.close()

        result = self._successReturn(True)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def lookup_keys(self, client_cert, credentials, options):
        method = 'lookup_keys'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        selected_columns, match_criteria = \
            unpack_query_options(options, MA.key_field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a "match" option')
        self.check_attributes(match_criteria)

        session = self.db.getSession()

        q = session.query(self.db.SSH_KEY_TABLE, \
                              self.db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self.db.SSH_KEY_TABLE.c.member_id == self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name=='urn')

        # Handle key_member specially : it is not part of the SSH key table
        if 'KEY_MEMBER' in match_criteria.keys():
            member_urn = match_criteria['KEY_MEMBER']
            if isinstance(member_urn, types.ListType):
                q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value.in_(member_urn))
            else:
                q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == member_urn)
            del match_criteria['KEY_MEMBER']

        q = add_filters(q, match_criteria, self.db.SSH_KEY_TABLE, MA.key_field_mapping)
        rows = q.all()
        session.close()
        keys = {}
        for row in rows:
            if row.value not in keys:
                keys[row.value] = []
            keys[row.value].append(construct_result_row(row, \
                         selected_columns, MA.key_field_mapping))
        result = self._successReturn(keys)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # Member certificate methods
    def create_certificate(self, client_cert, member_urn, credentials, options):
        method = 'create_certificate'
        args = {'member_urn' : member_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

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
            private_key, csr_file = make_csr()

        # Lookup UID and email from URN
        match = {'MEMBER_URN' : member_urn}
        lookup_options = {'match' : match}
        lookup_response = self.lookup_member_info(lookup_options,
                                                  ['MEMBER_EMAIL',
                                                   'MEMBER_UID'])
        member_info = lookup_response['value'][member_urn]
        member_email = str(member_info['MEMBER_EMAIL'])
        member_id = str(member_info['MEMBER_UID'])

        cert_pem = make_cert(member_id, member_email, member_urn,
                             self.cert, self.key, csr_file)

        # Grab signer pem
        signer_pem = open(self.cert).read()

        # This is the aggregate cert
        # Need to return it somehow
        cert_chain = cert_pem + signer_pem


        # Store cert and key in outside_cert table
        session = self.db.getSession()
        insert_fields={'certificate' : cert_chain, 'member_id' : member_id}
        if private_key:
            insert_fields['private_key'] = private_key
        ins = self.db.OUTSIDE_CERT_TABLE.insert().values(insert_fields)
        result = session.execute(ins)
        session.commit()
        session.close()

        result = self._successReturn(True)

        # chapi_audit call
        msg = "Created certificate for %s" % member_urn
        if private_key:
            msg = msg + " with private key"
        chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    ### ClientAuth

    # Dictionary of client_name => client_urn
    def list_clients(self, client_cert):
        method = 'list_clients'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, {}, {'user': user_email})

        session = self.db.getSession()
        q = session.query(self.db.MA_CLIENT_TABLE)
        rows = q.all()
        session.close()
        entries = {}
        for row in rows:
            entries[row.client_name] = row.client_urn
        result = self._successReturn(entries)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id):
        method = 'list_authorized_clients'
        args = {'member_id' : member_id}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})

        session = self.db.getSession()
        q = session.query(self.db.INSIDE_KEY_TABLE.c.client_urn)
        q = q.filter(self.db.INSIDE_KEY_TABLE.c.member_id == member_id)
        rows = q.all()
        session.close()
        entries = [str(row.client_urn) for row in rows]
        result = self._successReturn(entries)

        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # Authorize/deauthorize a tool with respect to a user
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense):
        method = 'authorize_client'
        args = {'member_id' : member_id, 'client_urn' : client_urn, 
                'authorize_sense' : authorize_sense}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})

        member_urn = convert_member_uid_to_urn(member_id)

        #chapi_audit(MA_LOG_PREFIX, "Called authorize_client "+member_id+' '+client_urn)
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
            msg = "Authorized client %s for member %s" % (client_urn, self._get_displayname_for_member_urn(member_urn))
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, member_id)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        else:
            # delete from MA_INSIDE_KEY_TABLENAME
            # where member_id = member_id and client_urn = client_urn
            session = self.db.getSession()
            q = session.query(InsideKey)
            q = q.filter(InsideKey.member_id == member_id)
            q = q.filter(InsideKey.client_urn == client_urn)
            q = q.delete()
            session.commit()
            session.close()

            # log_event
            msg = "Deauthorized client %s for member %s" % (client_urn, self._get_displayname_for_member_urn(member_urn))
            attribs = {"MEMBER" : member_id}
            self.logging_service.log_event(msg, attribs, member_id)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(True)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def mail_enable_user(self, msg, subject):
        msgbody = msg + " on " + self.config.get("chrm.authority")
        send_email(self.portal_admin_email, self.ch_from_email,self.portal_admin_email,subject,msgbody)

    # enable/disable a user/member  (private)
    def enable_user(self, client_cert, member_urn, enable_sense, credentials, options):
        '''Mark a member/user as enabled or disabled.
        IFF enabled_sense is True, then user is unconditionally enabled, otherwise disabled.
        returns the previous sense.'''
        method = 'enable_user'
        args = {'member_urn' : member_urn,
                'enable_sense' : enable_sense}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})

#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+str(enable_sense))

        session = self.db.getSession()
        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            session.close()
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_id = uids[0]

        # find the old value
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_id).\
            filter(MemberAttribute.name == MA.field_mapping['_GENI_MEMBER_ENABLED'])
        rows = q.all()

        if len(rows)==0:
            was_enabled = True
        else:
            was_enabled = (rows[0][0] == 'y')

        # set the new value
        enabled_str = 'y' if enable_sense else 'n'
        did_something = False
        if (not was_enabled and enable_sense) or (was_enabled and not enable_sense):
            did_something = True
            self.update_attr(session, '_GENI_MEMBER_ENABLED', enabled_str, member_id, 'f')

        session.commit()
        session.close()

        if did_something:
            # log_event
            msg = "Set member %s status to %s" % \
                (member_urn, 'enabled' if enable_sense else 'disabled')
            attribs = {"MEMBER" : member_urn}
            self.logging_service.log_event(msg, attribs, member_id)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})
            self.mail_enable_user(user_email + " " + msg, ("Enabled CH user" if enable_sense else "Disabled CH user"))
        else:
            chapi_info(MA_LOG_PREFIX, "Member %s already %s" % (member_urn, 'enabled' if enable_sense else 'disabled'), {'user': user_email})

        result = self._successReturn(was_enabled)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def check_user_enabled(self, client_cert):
        client_urn = get_urn_from_cert(client_cert)
        client_email = get_email_from_cert(client_cert)
        client_uuid = get_uuid_from_cert(client_cert)
        client_name = get_name_from_urn(client_urn)

        session = self.db.getSession()
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == client_uuid).\
            filter(MemberAttribute.name == MA.field_mapping['_GENI_MEMBER_ENABLED'])
        rows = q.all()
        is_enabled = (count(rows)==0 or rows[0][0] == 'y')
        session.close()

        if is_enabled:
            chapi_debug(MA_LOG_PREFIX, "CUE: user '%s' (%s) enabled" % (client_name, client_urn))
            pass
        else:
            chapi_audit_and_log(MA_LOG_PREFIX, "CUE: user '%s' (%s) disabled" % (client_name, client_urn), logging.INFO, {'user': user_email})
            raise CHAPIv1AuthorizationError("User %s (%s) disabled" % (client_name, client_urn));

    # send email about new lead/operator privilege
    def mail_new_privilege(self,member_id, privilege):
        options = {'match' : {'MEMBER_UID' : member_id },'filter': ['_GENI_MEMBER_DISPLAYNAME','MEMBER_FIRSTNAME','MEMBER_LASTNAME','MEMBER_EMAIL']}  
        info = self.lookup_member_info(options, MA.identifying_fields)
        member_info = info['value']
        pretty_name = ""
        member_email = None
        if len(member_info) > 0:
            for row in member_info:
                pretty_name = get_member_display_name(member_info[row],row)
                member_email = member_info[row]['MEMBER_EMAIL']
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
        
        #  msgbody .= "Please visit https://" . $_SERVER['SERVER_NAME'];
        #  msgbody .= "/secure/home.php for more information, or to get started.\n\n";
        
        msgbody += "Sincerely,\n"
        msgbody += "GENI Clearinghouse operations\n"

        send_email(member_email, self.ch_from_email,self.portal_help_email,subject,msgbody,self.portal_admin_email)

    #  member_privilege (private)
    def add_member_privilege(self, cert, member_uid, privilege, credentials, options):
        '''Mark a member/user as having a particular contextless privilege.
        privilege must be either OPERATOR or PROJECT_LEAD.'''
        method = 'add_member_privilege'
        args = {'member_id' : member_uid,
                'privilege' : privilege}
        user_email = get_email_from_cert(cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})

#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_uid+' '+privilege)

        if not (privilege in ['OPERATOR', 'PROJECT_LEAD']):
            raise CHAPIv1ArgumentError('Privilege %s undefined' % (privilege))

        session = self.db.getSession()

        # find the old value
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
            session.commit()

        session.close()

        if not was_enabled:
            # log_event
            msg = "Granted member %s privilege %s" %  (self._get_displayname_for_member_id(member_uid), privilege)
            attribs = {"MEMBER" : member_uid}
            self.logging_service.log_event(msg, attribs, member_uid)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

            # Email admins, new project lead/operator
            self.mail_new_privilege(member_uid,privilege)

        result = self._successReturn(not was_enabled)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def revoke_member_privilege(self, cert, member_uid, privilege, credentials, options):
        '''Mark a member/user as not having a particular contextless privilege.
        privilege must be either OPERATOR or PROJECT_LEAD.'''
        method = 'revoke_member_privilege'
        args = {'member_id' : member_uid,
                'privilege' : privilege}
        user_email = get_email_from_cert(cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_uid+' '+privilege)

        if not (privilege in ['OPERATOR', 'PROJECT_LEAD']):
            raise CHAPIv1ArgumentError('Privilege %s undefined' % (privilege))

        session = self.db.getSession()

        # find the old value
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

                projects = self._sa_handler._delegate.lookup_projects_for_member(cert, member_urn, credentials, {})

                for project in projects['value']:
                    new_lead_urn = None
                    if (project['EXPIRED'] == False and project['PROJECT_ROLE'] == 'LEAD'):
                        project_urn = project['PROJECT_URN']
                        #look for authorized admin to be new lead
                        members = self._sa_handler._delegate.lookup_project_members(cert, project_urn, credentials, {})
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
                                    result = self._sa_handler._delegate.modify_project_membership(cert, project['PROJECT_URN'], credentials, options)
                                    break
                        if new_lead_urn == None:
                            session.close()
                            raise CHAPIv1ArgumentError('Cannot revoke lead privilege.  No authorized admin to take lead role on project %s' %project_urn)                            
        if was_enabled:
            self.delete_attr(session, privilege, member_uid)

        session.close()

        if was_enabled:
            # log_event
            msg = "Revoked member %s privilege %s" %  (self._get_displayname_for_member_id(member_uid), privilege)
            attribs = {"MEMBER" : member_uid}
            self.logging_service.log_event(msg, attribs, member_uid)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(was_enabled)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    #  member_attribute (private)
    def add_member_attribute(self, cert, member_urn, attr_name, attr_value, attr_self_assert,
                             credentials, options):
        method = 'add_member_attribute'
        args = {'member_urn' : member_urn,
                'name' : attr_name,
                'value' : attr_value,
                'self_assert' : attr_self_assert}
        user_email = get_email_from_cert(cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})

#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+attr_name+' = '+attr_value)

        if attr_name in ['PROJECT_LEAD', 'OPERATOR']:
            raise CHAPIv1ArgumentError('%s not a valid member attribute' % attr_name)

        session = self.db.getSession()
        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            session.close()
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_uid = uids[0]

        # find the old value
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == attr_name)
        rows = q.all()

        was_defined = (len(rows)>0)
        old_value = None
        if was_defined:
            old_value = rows[0][0]
            if old_value != attr_value:
                was_defined = False

        if not was_defined:
            self.update_attr(session, attr_name, attr_value, member_uid, attr_self_assert)
        session.commit()
        session.close()

        if not was_defined:
            # log_event
            msg = "Set member %s attribute %s to %s" %  (self._get_displayname_for_member_urn(member_urn), attr_name, attr_value )
            attribs = {"MEMBER" : member_urn}
            self.logging_service.log_event(msg, attribs, member_uid)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(old_value)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def remove_member_attribute(self, cert, member_urn, attr_name, credentials, options):
        method = 'remove_member_attribute'
        args = {'member_urn' : member_urn,
                'name' : attr_name}
        user_email = get_email_from_cert(cert)
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args, {'user': user_email})
#        chapi_audit(MA_LOG_PREFIX, "Called " + method+' '+member_urn+' '+attr_name)

        if attr_name in ['PROJECT_LEAD', 'OPERATOR']:
            raise CHAPIv1ArgumentError('%s not a valid member attribute' % attr_name)

        session = self.db.getSession()
        # find the uid
        uids = self.get_uids_for_attribute(session, "MEMBER_URN", member_urn)
        if len(uids) == 0:
            session.close()
            raise CHAPIv1ArgumentError('No member with URN ' + member_urn)
        member_uid = uids[0]

        # find the old value
        q = session.query(MemberAttribute.value).\
            filter(MemberAttribute.member_id == member_uid).\
            filter(MemberAttribute.name == attr_name)
        rows = q.all()

        was_defined = (len(rows)>0)

        chapi_debug(MA_LOG_PREFIX, 'RMA.ROWS = %s' % rows, {'user': user_email})

        old_value = None
        if was_defined:
            old_value = rows[0][0]
            self.delete_attr(session, attr_name, member_uid)

        session.close()

        if was_defined:
            # log_event
            msg = "Removed member %s attribute %s" %  (self._get_displayname_for_member_urn(member_urn), attr_name)
            attribs = {"MEMBER" : member_urn}
            self.logging_service.log_event(msg, attribs, member_uid)
            chapi_audit_and_log(MA_LOG_PREFIX, msg, logging.INFO, {'user': user_email})

        result = self._successReturn(old_value)
        chapi_log_result(MA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def _get_displayname_for_member_id(self, member_id):
        member_urn = convert_member_uid_to_urn(member_id)
        return self._get_displayname_for_member_urn(member_urn)

    def _get_displayname_for_member_urn(self, member_urn):
        urns = []
        urns.append(member_urn)
        options = {\
            "match" : {"MEMBER_URN" : urns}, 
            "filter" : ["_GENI_MEMBER_DISPLAYNAME", "MEMBER_FIRSTNAME", 
                        "MEMBER_LASTNAME", "MEMBER_EMAIL"]}
        result = self.lookup_member_info(options, MA.identifying_fields)
        if result['code'] != NO_ERROR or member_urn not in result['value']:
            return member_urn
        else:
            return get_member_display_name(result['value'][member_urn], member_urn)
