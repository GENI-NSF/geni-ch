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

from chapi.MemberAuthority import MAv1DelegateBase
from chapi.Exceptions import *
from geni.util.urn_util import URN
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from tools.cert_utils import *
from tools.chapi_log import *
import sfa.trust.gid as sfa_gid
import sfa.trust.certificate as cert
import geni.util.cred_util as cred_util
from sqlalchemy.orm import mapper
from datetime import *
from dateutil.relativedelta import relativedelta
import os
import tempfile
import subprocess
import uuid
import re
from tools.guard_utils import *
from syslog import syslog

# classes for mapping to sql tables

class MemberAttribute(object):
    def __init__(self, name, value, member_id, self_asserted):
        self.name = name
        self.value = value
        self.member_id = member_id
        self.self_asserted = self_asserted
        self.logging_service = pm.getService('loggingv1handler')

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
    q = q.filter(MemberAttribute.name == name)
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

    version_number = "1.0"
    credential_types = ["SFA", "ABAC"]

    standard_fields = {
        "MEMBER_URN" : { "TYPE" : " URN" , 
                             "UPDATE" : False, "PROTECT" : "PUBLIC"},
        "MEMBER_UID": { "TYPE" : "UID", "UPDATE" : False, \
                            "PROTECT" : "PUBLIC"},
        "MEMBER_FIRSTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
        "MEMBER_LASTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
        "MEMBER_USERNAME" : {"TYPE" : "STRING", "PROTECT" : "PUBLIC"},
        "MEMBER_EMAIL" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"}
        }

    optional_fields = {
        "_GENI_MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_PHONE_NUMBER": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                                "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_EPPN": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                        "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_SSL_PUBLIC_KEY": {"TYPE": "KEY"},
        "_GENI_MEMBER_SSL_CERTIFICATE": {"TYPE": "CERTIFICATE"},
        "_GENI_MEMBER_SSL_PRIVATE_KEY": \
                      {"TYPE": "KEY", "PROTECT": "PRIVATE"},
        "_GENI_MEMBER_INSIDE_PUBLIC_KEY": {"TYPE": "KEY"},
        "_GENI_MEMBER_INSIDE_CERTIFICATE": {"TYPE": "CERTIFICATE"},
        "_GENI_MEMBER_INSIDE_PRIVATE_KEY": \
                      {"TYPE": "KEY", "PROTECT": "PRIVATE"},
        "_GENI_USER_CREDENTIAL": {"TYPE": "CREDENTIAL"}
        }

    standard_key_fields = { 
        "KEY_MEMBER" : \
            {"TYPE" : "URN", "CREATE" : "REQUIRED"}, \
            "KEY_ID" : {"TYPE" : "UID"}, \
            "KEY_PUBLIC" : \
            {"TYPE" : "KEY", "CREATE" : "REQUIRED"},  \
            "KEY_PRIVATE" : \
            {"TYPE" : "KEY", "CREATE" : "ALLOWED"}, \
            "KEY_DESCRIPTION" : \
            {"TYPE" : "STRING", "CREATE" : "ALLOWED", "UPDATE" : True} 
    }

    optional_key_fields = {
        "_GENI_KEY_FILENAME" : {"TYPE" : "STRING", "UPDATE" : True, \
                                    "CREATE" : "ALLOWED"}
	}
    
    # Mapping from external to internal data schema
    field_mapping = {
        "MEMBER_URN": "urn",
        "MEMBER_UID": "member_id",
        "MEMBER_FIRSTNAME": "first_name",
        "MEMBER_LASTNAME": "last_name",
        "MEMBER_USERNAME": "username",
        "MEMBER_EMAIL": "email_address",
        "_GENI_MEMBER_DISPLAYNAME": "displayName",
        "_GENI_MEMBER_PHONE_NUMBER": "telephone_number",
        "_GENI_MEMBER_AFFILIATION": "affiliation",
        "_GENI_MEMBER_EPPN": "eppn",
        "_GENI_MEMBER_SSL_CERTIFICATE": "certificate",
        "_GENI_MEMBER_SSL_PUBLIC_KEY": row_cert_to_public_key, 
        "_GENI_MEMBER_SSL_PRIVATE_KEY": "private_key",
        "_GENI_MEMBER_INSIDE_PUBLIC_KEY": row_cert_to_public_key,
        "_GENI_MEMBER_INSIDE_CERTIFICATE": "certificate",
        "_GENI_MEMBER_INSIDE_PRIVATE_KEY": "private_key",
        "_GENI_USER_CREDENTIAL": "foo"
        }

    key_fields = ["KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", 
                  "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", 
                  "_GENI_KEY_FILENAME" ]
    key_field_mapping = {
        "KEY_MEMBER": 'value',
        "KEY_ID": 'id',
        "KEY_PUBLIC": "public_key",
        "KEY_PRIVATE": "private_key",
        "KEY_DESCRIPTION":  "description",
        "_GENI_KEY_MEMBER_UID": "member_id",
        "_GENI_KEY_FILENAME": "filename"
        }

    objects = ["MEMBER", "KEY"]
    services = ["MEMBER", "KEY"]

    attributes = ["MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", \
                      "MEMBER_LASTNAME", "MEMBER_USERNAME", "MEMBER_EMAIL", \
                      "_GENI_MEMBER_DISPLAYNAME", "_GENI_MEMBER_PHONE_NUMBER", \
                      "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN", \
                      "KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", \
                      "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", \
                      "_GENI_KEY_FILENAME"]

    public_fields = ["MEMBER_URN", "MEMBER_UID", "MEMBER_USERNAME", \
                         "_GENI_MEMBER_SSL_PUBLIC_KEY", "_GENI_MEMBER_SSL_CERTIFICATE", \
                         "_GENI_MEMBER_INSIDE_PUBLIC_KEY", "_GENI_MEMBER_INSIDE_CERTIFICATE", \
                         "_GENI_USER_CREDENTIAL"]

    identifying_fields = ["MEMBER_FIRSTNAME", "MEMBER_LASTNAME", \
                              "MEMBER_USERNAME", \
                              "MEMBER_EMAIL", \
                              "MEMBER_URN", "MEMBER_UID", \
                              "_GENI_MEMBER_DISPLAYNAME", "_GENI_MEMBER_PHONE_NUMBER", \
                     "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN"]

    private_fields = ["_GENI_MEMBER_SSL_PRIVATE_KEY", \
                          "MEMBER_URN", "MEMBER_UID", \
                          "_GENI_MEMBER_INSIDE_PRIVATE_KEY"]

    key_fields = ["KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", 
                  "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", 
                  "_GENI_KEY_FILENAME" ]

    required_create_key_fields = ["KEY_PUBLIC"]
    allowed_create_key_fields = ["KEY_PUBLIC", "KEY_PRIVATE", "KEY_DESCRIPTION", "_GENI_KEY_FILENAME"]
    updatable_key_fields = ["KEY_DESCRIPTION"]
    
    def __init__(self):
        super(MAv1Implementation, self).__init__()
        self.db = pm.getService('chdbengine')
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
        self.cert = '/usr/share/geni-ch/ma/ma-cert.pem'
        self.key = '/usr/share/geni-ch/ma/ma-key.pem'
        trusted_root = '/usr/share/geni-ch/portal/gcf.d/trusted_roots'
        self.trusted_roots = [os.path.join(trusted_root, f) \
            for f in os.listdir(trusted_root) if not f.startswith('CAT')]

        self.logging_service = pm.getService('loggingv1handler')
        # init for ClientAuth
        self.kmcert = '/usr/share/geni-ch/km/km-cert.pem'
        self.kmkey = '/usr/share/geni-ch/km/km-key.pem'


    # This call is unprotected: no checking of credentials
    def get_version(self):
        method = 'get_version'
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, {})

        all_optional_fields = dict(self.optional_fields.items() + \
                                   self.optional_key_fields.items())
        version_info = {"VERSION": self.version_number,
                        "CREDENTIAL_TYPES": self.credential_types,
                        "OBJECTS" : self.objects,
                        "SERVICES" : self.services,
                        "FIELDS": all_optional_fields}
        result =  self._successReturn(version_info)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # ensure that all of a set of entries are attributes
    def check_attributes(self, attrs):
        for attr in attrs:
            if attr not in self.attributes:
                raise CHAPIv1ArgumentError('Unknown attribute ' + attr)

    # filter out all the users that have a particular value of an attribute
    def get_uids_for_attribute(self, session, attr, value):
        if attr == 'MEMBER_UID':  # If we already have the UID, return it
            if isinstance(value, list):
                return value
            else:
                return [value]
        q = session.query(MemberAttribute.member_id)
        q = q.filter(MemberAttribute.name == self.field_mapping[attr])
        if isinstance(value, types.ListType):
            q = q.filter(MemberAttribute.value.in_(value))
        else:
            q = q.filter(MemberAttribute.value == value)
        rows = q.all()
        return [row.member_id for row in rows]

    # find the value of an attribute for a given user
    def get_attr_for_uid(self, session, attr, uid):
        q = session.query(MemberAttribute.value)
        q = q.filter(MemberAttribute.name == self.field_mapping[attr])
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
            unpack_query_options(options, self.field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a "match" option')
        self.check_attributes(match_criteria)
        selected_columns = set(selected_columns) & set(allowed_fields)
        session = self.db.getSession()

        # first, get all the member ids of matches
        uids = [set(self.get_uids_for_attribute(session, attr, value)) \
                for attr, value in match_criteria.iteritems()]
        uids = set.intersection(*uids)

        # then, get the values
        members = {}
        for uid in uids:
            urn = self.get_attr_for_uid(session, "MEMBER_URN", uid)[0]
            values = {}
            for col in selected_columns:
                if col == "_GENI_USER_CREDENTIAL":
                    values[col] = self.get_user_credential(session, uid)
                elif col == "MEMBER_UID":
                    values[col] = uid
                else:
                    vals = None
                    if col in self.attributes:
                        vals = self.get_attr_for_uid(session, col, uid)
                    elif col in self.table_mapping:
                        vals = self.get_val_for_uid(session, \
                            self.table_mapping[col], self.field_mapping[col], uid)
                    if vals:
                        values[col] = vals[0]
                    elif 'filter' in options:
                        values[col] = None
            members[urn] = values

        session.close()
        return self._successReturn(members)

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, credentials, options):
        method = 'lookup_public_member_info'
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {})

        result = self.lookup_member_info(options, self.public_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        method = 'lookup_private_member_info'
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {})

        result = self.lookup_member_info(options, self.private_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        method = 'lookup_identifying_member_info'
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {})

        result = self.lookup_member_info(options, self.identifying_fields)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
        method = 'update_member_info'
        args = {'member_urn' : member_urn}
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

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
            if attr in self.attributes:
                self.update_attr(session, attr, value, uid, self_asserted)
            elif attr in self.table_mapping:
                table = self.table_mapping[attr]
                if table not in all_keys:
                    all_keys[table] = {}
                all_keys[table][self.field_mapping[attr]] = value
        for table, keys in all_keys.iteritems():
            self.update_keys(session, table, keys, uid)
            
        session.close()

        result = self._successReturn(True)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # update or insert value of attribute attr for user uid
    def update_attr(self, session, attr, value, uid, self_asserted):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            q = session.query(MemberAttribute)
            q = q.filter(MemberAttribute.name == self.field_mapping[attr])
            q = q.filter(MemberAttribute.member_id == uid)
            q.update({"value": value})
        else:
            obj = MemberAttribute(self.field_mapping[attr], value, \
                                  uid, self_asserted)
            session.add(obj)
        session.commit()

    # update or insert into one of the two SSL key tables
    def update_keys(self, session, table, keys, uid):
        if self.get_val_for_uid(session, table, "certificate", uid):
            q = session.query(table)
            q = q.filter(getattr(table, "member_id") == uid)
            q.update(keys)
        else:
            if "certificate" not in keys:
                raise CHAPIv1ArgumentError('Cannot insert just private key')
            obj = table()
            obj.member_id = uid
            for key, val in keys.iteritems():
                 setattr(obj, key, val)
            session.add(obj)
        session.commit()

    # delete all existing ssl keys, and replace them with specified ones
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

    # build a user credential based on the user's cert
    def get_user_credential(self, session, uid):
        certs = self.get_val_for_uid(session, OutsideCert, "certificate", uid)
        if not certs:
            certs = self.get_val_for_uid(session, InsideKey, "certificate", uid)
        if not certs:
            return None
        gid = sfa_gid.GID(string = certs[0])
        expires = datetime.utcnow() + relativedelta(years=1)
        cred = cred_util.create_credential(gid, gid, expires, "user", \
                  self.key, self.cert, self.trusted_roots)
        return cred.save_to_string()

    def create_member(self, client_cert, attributes, credentials, options):

        method = 'create_member'
        args = {'attributes' : attributes}
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

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
        msg = "Activated GENI user : %s" % member_id
        attrs = {"MEMBER" : member_id}
        self.logging_service.log_event(msg, attrs, member_id)

        result = self._successReturn(atmap.values())

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # Implementation of KEY Service methods

    def create_key(self, client_cert, member_urn, credentials, options):
        
        method = 'create_key'
        args = {'member_urn' : member_urn}
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

       # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No fields in create_key")
        fields = options['fields']
        validate_fields(fields, self.required_create_key_fields, \
                            self.allowed_create_key_fields)
        create_fields = \
            convert_dict_to_internal(fields, self.key_field_mapping)

        # Add member_id to create_fields
        lookup_member_id_options = {'match' : {'MEMBER_URN' : member_urn},
                                    'filter' : ['MEMBER_UID']}
        result = \
            self.lookup_public_member_info(credentials, \
                                               lookup_member_id_options)
        if result['code'] != NO_ERROR:
            return result # Shouldn't happen: Should raise exception instead

        member_id = result['value'][member_urn]['MEMBER_UID']
        create_fields['member_id'] = member_id

        session = self.db.getSession()
        ins = self.db.SSH_KEY_TABLE.insert().values(create_fields)
        result = session.execute(ins)
        key_id = result.inserted_primary_key[0]
        fields["KEY_ID"] = key_id
        fields["KEY_MEMBER"] = member_urn

        session.commit()
        session.close()

        # Log the creation of the SSH key
        client_uuid = get_uuid_from_cert(ciient_cert)
        attrs = {"MEMBER" : client_uuid}
        msg = "%s registering SSH key %s" % (member_urn, key_id)
        self.logging_service.log_event(msg, attrs, client_uuid)

        result = self._successReturn(fields)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    def delete_key(self, client_cert, member_urn, key_id, \
                       credentials, options):

        method = 'delete_key'
        args = {'member_id' : member_id, 'key_id' : key_id}
        chap_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

        session = self.db.getSession()
        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
        num_del = q.delete()
        if num_del == 0:
            raise CHAPIv1DatabaseError("No key with id  %s" % key_id)
        session.commit()
        session.close()

        # Log the deletion of the SSH key
        client_uuid = get_uuid_from_cert(ciient_cert)
        attrs = {"MEMBER" : client_uuid}
        msg = "%s deleting SSH key %s" % (member_urn, key_id)
        self.logging_service.log_event(msg, attrs, client_uuid)

        result = self._successReturn(True)
        
        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    def update_key(self, client_cert, member_urn, key_id, \
                       credentials, options):

        method = 'update_key'
        args = {'member_urn' : member_urn, 'key_id' : key_id}
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

        # Check that all the fields are allowed to be updated
        if 'fields' not in options:
            raise CHAPIv1ArgumentError("No fields in update_key")
        fields = options['fields']
        validate_fields(fields, None, self.updatable_key_fields)
        update_fields = \
            convert_dict_to_internal(fields, self.key_field_mapping)
        session = self.db.getSession()
        q = session.query(SshKey)
        q = q.filter(SshKey.id == key_id)
#        print "UPDATE_FIELDS = " + str(update_fields)
        num_upd = q.update(update_fields)

        if num_upd == 0:
            raise CHAPIv1DatabaseError("No key with id %s" % key_id)
        session.commit()
        session.close()

        result = self._successReturn(True)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    def lookup_keys(self, client_cert, credentials, options):
        method = 'lookup_keys'
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, {})

        selected_columns, match_criteria = \
            unpack_query_options(options, self.key_field_mapping)
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

        q = add_filters(q, match_criteria, self.db.SSH_KEY_TABLE, self.key_field_mapping)
        rows = q.all()
        session.close()

        keys = [construct_result_row(row, selected_columns, \
                                         self.key_field_mapping) \
                    for row in rows]
        result = self._successReturn(keys)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # Member certificate methods
    def create_certificate(self, client_cert, member_urn, \
                               credentials, options):
        method = 'create_certificate'
        args = {'member_urn' : member_urn}
        chapi_log_invocation(MA_LOG_PREFIX, method, credentials, options, args)

#        print "In MAv1Implementation.create_cert : " + \
#            str(member_urn) + " " + str(options)

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
        lookup_response = \
            self.lookup_member_info(lookup_options, \
                                        ['MEMBER_EMAIL', 'MEMBER_UID'])
        member_info = lookup_response['value'][member_urn]
        urn = member_urn
        email = str(member_info['MEMBER_EMAIL'])
        uuid = str(member_info['MEMBER_UID'])

        cert_pem, private_key = \
            make_cert_and_key(member_id, member_email, \
                                  member_urn, self.cert, self.key, csr_file)

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
        ins = self.db.OUTSIDE_CERT_TABLE().values(insert_fields)
        result = session.execute(ins)
        session.commit()
        session.close()

        result = self._successReturn(True)
        
        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    ### ClientAuth

    # Dictionary of client_name => client_urn
    def list_clients(self):
        method = 'list_clients'
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, {})

        session = self.db.getSession()
        q = session.query(self.db.MA_CLIENT_TABLE)
        rows = q.all()
        session.close()
        entries = {}
        for row in rows:
            entries[row.client_name] = row.client_urn
        result = self._successReturn(entries)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # List of URN's of all tools for which a given user (by ID) has
    # authorized use and has generated inside keys
    def list_authorized_clients(self, client_cert, member_id):
        method = 'list_authorized_clients'
        args = {'member_id' : member_id}
        chapi_log_invocation(MA_LOG_PREFIX, method, [], {}, args)

        session = self.db.getSession()
        q = session.query(self.db.INSIDE_KEY_TABLE.c.client_urn)
        q = q.filter(self.db.INSIDE_KEY_TABLE.c.member_id == member_id)
        rows = q.all()
        session.close()
        entries = [str(row.client_urn) for row in rows]
        result = self._successReturn(entries)

        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

    # Authorize/deauthorize a tool with respect to a user
    def authorize_client(self, client_cert, member_id, \
                             client_urn, authorize_sense):
        method = 'authorize_client'
        args = {'member_id' : member_id, 'client_urn' : client_urn, 
                'authorize_sense' : authorize_sense}
        chapi_log_invoation(MA_LOG_PREFIX, method, [], {}, args)

        member_urn = convert_member_uid_to_urn(member_id)

        syslog("authorize_client "+member_id+' '+client_urn)
        if authorize_sense:
            private_key, csr_file = make_csr()
            member_email = convert_member_uid_to_email(member_id)
            cert_pem = make_cert(member_id, member_email, member_urn, \
                                     self.kmcert, self.kmkey, csr_file)

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

        result = self._successReturn(True)
        chapi_log_result(MA_LOG_PREFIX, method, result)
        return result

