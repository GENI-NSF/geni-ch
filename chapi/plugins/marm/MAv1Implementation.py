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
from ext.geni.util.urn_util import URN
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
import ext.sfa.trust.gid as sfa_gid
import geni.util.cred_util as cred_util
from sqlalchemy.orm import mapper
from datetime import *
from dateutil.relativedelta import relativedelta
import os


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


class MAv1Implementation(MAv1DelegateBase):

    version_number = "1.0"
    credential_types = ["SFA", "ABAC"]
    optional_fields = {
        "_GENI_MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_PHONE_NUMBER": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                                "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_EPPN": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                        "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "_GENI_MEMBER_SSL_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "_GENI_MEMBER_SSL_PRIVATE_KEY": \
                      {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "_GENI_MEMBER_INSIDE_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "_GENI_MEMBER_INSIDE_PRIVATE_KEY": \
                      {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "_GENI_MEMBER_SSH_KEYS": {"TYPE": "SSH_KEYS"},
        "_GENI_USER_CREDENTIAL": {"TYPE": "CREDENTIAL"}
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
        "_GENI_MEMBER_SSL_PUBLIC_KEY": "certificate",
        "_GENI_MEMBER_SSL_PRIVATE_KEY": "private_key",
        "_GENI_MEMBER_INSIDE_PUBLIC_KEY": "certificate",
        "_GENI_MEMBER_INSIDE_PRIVATE_KEY": "private_key",
        "_GENI_USER_CREDENTIAL": "foo",
        "_GENI_MEMBER_SSH_KEYS": "foo"
        }

    attributes = ["MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", \
                  "MEMBER_LASTNAME", "MEMBER_USERNAME", "MEMBER_EMAIL", \
                  "_GENI_MEMBER_DISPLAYNAME", "_GENI_MEMBER_PHONE_NUMBER", \
                  "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN"]

    public_fields = ["MEMBER_URN", "MEMBER_UID", "MEMBER_USERNAME", \
             "_GENI_MEMBER_SSL_PUBLIC_KEY", "_GENI_MEMBER_INSIDE_PUBLIC_KEY", \
             "_GENI_USER_CREDENTIAL", "_GENI_MEMBER_SSH_KEYS"]

    identifying_fields = ["MEMBER_FIRSTNAME", "MEMBER_LASTNAME", "MEMBER_EMAIL", \
                     "_GENI_MEMBER_DISPLAYNAME", "_GENI_MEMBER_PHONE_NUMBER", \
                     "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN"]

    private_fields = ["_GENI_MEMBER_SSL_PRIVATE_KEY", \
                "_GENI_MEMBER_INSIDE_PRIVATE_KEY", "_GENI_MEMBER_SSH_KEYS"]


    def __init__(self):
        self.db = pm.getService('chdbengine')
        mapper(MemberAttribute, self.db.MEMBER_ATTRIBUTE_TABLE)
        mapper(OutsideCert, self.db.OUTSIDE_CERT_TABLE)
        mapper(InsideKey, self.db.INSIDE_KEY_TABLE)
        mapper(SshKey, self.db.SSH_KEY_TABLE)
        self.table_mapping = {
            "_GENI_MEMBER_SSL_PUBLIC_KEY": OutsideCert,
            "_GENI_MEMBER_SSL_PRIVATE_KEY": OutsideCert,
            "_GENI_MEMBER_INSIDE_PUBLIC_KEY": InsideKey,
            "_GENI_MEMBER_INSIDE_PRIVATE_KEY": InsideKey
            }
        self.cert = '/usr/share/geni-ch/ma/ma-cert.pem'
        self.key = '/usr/share/geni-ch/ma/ma-key.pem'
        trusted_root = '/usr/share/geni-ch/portal/gcf.d/trusted_roots'
        self.trusted_roots = [os.path.join(trusted_root, f) \
            for f in os.listdir(trusted_root) if not f.startswith('CAT')]

    # This call is unprotected: no checking of credentials
    def get_version(self):
        version_info = {"VERSION": self.version_number,
                        "CREDENTIAL_TYPES": self.credential_types,
                        "FIELDS": self.optional_fields}
        return self._successReturn(version_info)

    # ensure that all of a set of entries are attributes
    def check_attributes(self, attrs):
        for attr in attrs:
            if attr not in self.attributes:
                raise CHAPIv1ArgumentError('Unknown attribute ' + attr)

    # filter out all the users that have a particular value of an attribute
    def get_uids_for_attribute(self, session, attr, value):
        q = session.query(MemberAttribute.member_id)
        q = q.filter(MemberAttribute.name == self.field_mapping[attr])
        if isinstance(value, types.ListType):
            q = q.filter(MemberAttribute.value._in(value))
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
        q = session.query(getattr(table, field))
        q = q.filter(table.member_id == uid)
        rows = q.all()
        return [getattr(row, field) for row in rows]

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
                elif col == "_GENI_MEMBER_SSH_KEYS":
                    values[col] = self.get_ssh_keys_for_uid(session, uid, \
                                    allowed_fields == self.private_fields)
                else:
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
        return self.lookup_member_info(options, self.public_fields)

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        return self.lookup_member_info(options, self.private_fields)

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        return self.lookup_member_info(options, self.identifying_fields)

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
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
            elif attr == "_GENI_MEMBER_SSH_KEYS":
                self.update_ssh_keys(session, value, uid)
        for table, keys in all_keys.iteritems():
            self.update_keys(session, table, keys, uid)
            
        session.close()
        return self._successReturn(True)

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
        expires = datetime.now() + relativedelta(years=1)
        cred = cred_util.create_credential(gid, gid, expires, "user", \
                  self.key, self.cert, self.trusted_roots)
        return cred.save_to_string()
