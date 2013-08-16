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
import ext.sfa.trust.credential as sfa_cred
import ext.sfa.trust.gid as sfa_gid
import ext.geni.util.cert_util as cert_util

# Utility functions for morphing from native schema to public-facing
# schema

def urn_to_user_credential(urn):
    cred = sfa_cred.Credential()
    gid, keys = cert_util.create_cert(str(urn))
    cred.set_gid_object(gid)
    cred.set_gid_caller(gid)
    return cred.save_to_string()


class MAv1Implementation(MAv1DelegateBase):

    version_number = "1.0"
    credential_types = ["SFA", "ABAC"]
    optional_fields = {
        "MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "MEMBER_PHONE_NUMBER": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                                "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "MEMBER_EPPN": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                        "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "MEMBER_SSL_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "MEMBER_SSL_PRIVATE_KEY": {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "MEMBER_INSIDE_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "MEMBER_INSIDE_PRIVATE_KEY": {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "MEMBER_SSH_KEYS": {"TYPE": "SSH_KEYS"},
        "USER_CREDENTIAL": {"TYPE": "CREDENTIAL"}
	}

    # Mapping from external to internal data schema
    field_mapping = {
        "MEMBER_URN": "urn",
        "MEMBER_UID": "member_id",
        "MEMBER_FIRSTNAME": "first_name",
        "MEMBER_LASTNAME": "last_name",
        "MEMBER_USERNAME": "username",
        "MEMBER_EMAIL": "email_address",
        "MEMBER_DISPLAYNAME": "displayName",
        "MEMBER_PHONE_NUMBER": "telephone_number",
        "MEMBER_AFFILIATION": "affiliation",
        "MEMBER_EPPN": "eppn",
        "MEMBER_SSL_PUBLIC_KEY": "certificate",
        "MEMBER_SSL_PRIVATE_KEY": "private_key",
        "MEMBER_INSIDE_PUBLIC_KEY": "certificate",
        "MEMBER_INSIDE_PRIVATE_KEY": "private_key",
        "USER_CREDENTIAL": urn_to_user_credential,
        "MEMBER_SSH_KEYS": "urn_to_ssh_keys"
        }

    attributes = ["MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", \
                  "MEMBER_LASTNAME", "MEMBER_USERNAME", "MEMBER_EMAIL", \
                  "MEMBER_DISPLAYNAME", "MEMBER_PHONE_NUMBER", \
                  "MEMBER_AFFILIATION", "MEMBER_EPPN"]

    public_fields = ["MEMBER_URN", "MEMBER_UID", "MEMBER_USERNAME", \
                     "MEMBER_SSL_PUBLIC_KEY", "MEMBER_INSIDE_PUBLIC_KEY", \
                     "USER_CREDENTIAL", "MEMBER_SSH_KEYS"]

    identifying_fields = ["MEMBER_FIRSTNAME", "MEMBER_LASTNAME", "MEMBER_EMAIL", \
                          "MEMBER_DISPLAYNAME", "MEMBER_PHONE_NUMBER", \
                          "MEMBER_AFFILIATION", "MEMBER_EPPN"]

    private_fields = ["MEMBER_SSL_PRIVATE_KEY", "MEMBER_INSIDE_PRIVATE_KEY", \
                      "MEMBER_SSH_KEYS"]


    def __init__(self):
        self.db = pm.getService('chdbengine')
        self.table_mapping = {
            "MEMBER_SSL_PUBLIC_KEY": self.db.OUTSIDE_CERT_TABLE,
            "MEMBER_SSL_PRIVATE_KEY": self.db.OUTSIDE_CERT_TABLE,
            "MEMBER_INSIDE_PUBLIC_KEY": self.db.INSIDE_KEY_TABLE,
            "MEMBER_INSIDE_PRIVATE_KEY": self.db.INSIDE_KEY_TABLE,
            }

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
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == \
                     self.field_mapping[attr])
        if isinstance(value, types.ListType):
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value._in(value))
        else:
            q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == value)
        rows = q.all()
        return [row.member_id for row in rows]

    # find the value of an attribute for a given user
    def get_attr_for_uid(self, session, attr, uid):
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == \
                     self.field_mapping[attr])
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == uid)
        rows = q.all()
        return [row.value for row in rows]

    # find the value for a column in a table
    def get_val_for_uid(self, session, table, field, uid):
        q = session.query(table.c[field])
        q = q.filter(table.c.member_id == uid)
        rows = q.all()
        return [getattr(row, field) for row in rows]

    # construct a list of ssh keys
    def get_ssh_keys_for_uid(self, session, uid, include_private):
        q = session.query(self.db.SSH_KEY_TABLE)
        q = q.filter(self.db.SSH_KEY_TABLE.c.member_id == uid)
        rows = q.all()
        excluded = ['id', 'member_id'] + [['private_key'], []][include_private]
        return [{key: getattr(row, key) for key in row.keys() if key \
                  not in excluded } for row in rows]

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
                if col == "USER_CREDENTIAL":
                    values[col] = urn_to_user_credential(urn)
                elif col == "MEMBER_SSH_KEYS":
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
        # preliminary error checking
        if 'update' not in options:
            raise CHAPIv1ArgumentError('Missing an update key')
        new_attrs = options['update']
        if not isinstance(new_attrs, types.DictType):
            raise CHAPIv1ArgumentError('update value should be dictionary')

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
        for attr, value in new_attrs.iteritems():
            if attr in self.attributes:
                self.update_attr(session, attr, value, uid, self_asserted)
            elif attr in self.table_mapping:
                table = self.table_mapping[attr]
                if table not in all_keys:
                    all_keys[table] = {}
                all_keys[table][self.field_mapping[attr]] = value
            elif attr == "MEMBER_SSH_KEYS":
                self.update_ssh_keys(session, value, uid)
        for table, keys in all_keys.iteritems():
            self.update_keys(session, table, keys, uid)
            
        session.close()
        return self._successReturn(True)

    def update_attr(self, session, attr, value, uid, self_asserted):
        if len(self.get_attr_for_uid(session, attr, uid)) > 0:
            sql = "update " + self.db.MEMBER_ATTRIBUTE_TABLE.name + \
                  " set value='" + value + "', self_asserted='" + \
                  self_asserted + "' where name='" + \
                  self.field_mapping[attr] + "' and member_id='" + uid + "';"
        else:
            sql = "insert into " + self.db.MEMBER_ATTRIBUTE_TABLE.name + \
                  " (name, value, member_id, self_asserted) values ('" + \
                  self.field_mapping[attr] + "', '" + value + "', '" + \
                  uid + "', '" + self_asserted + "');"
        print 'sql = ', sql
        res = session.execute(sql)
        session.commit()

        # couldn't get this to work for update
#        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE)
#        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == \
#                     self.field_mapping[attr])
#        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == uid)
#        q.update({self.db.MEMBER_ATTRIBUTE_TABLE.c.value: value})

    def update_keys(self, session, table, keys, uid):
        if self.get_val_for_uid(session, table, "certificate", uid):
            text = ""
            for field, value in keys.iteritems():
                if text: text += ", "
                text += field + "='" + value + "'"
            sql = "update " + table.name + " set " + text + \
                  " where member_id='" + uid + "';"
        else:
            if "certificate" not in keys:
                raise CHAPIv1ArgumentError('Cannot insert just private key')
            text1, text2 = "", ""
            if "private_key" in keys:
                text1 = ", private_key"
                text2 = "', '" + keys["private_key"]
            sql = "insert into " + self.db.OUTSIDE_CERT_TABLE.name + \
                  " (member_id, certificate" + text1 + ") values ('" + uid + \
                  "', '" + keys["certificate"] + text2 + "');"
        print 'sql = ', sql
        res = session.execute(sql)
        session.commit()

    def update_ssh_keys(self, session, keys, uid):
        sql = "delete from " + self.db.SSH_KEY_TABLE.name + \
              " where member_id='" + uid + "';"
        session.execute(sql)
        session.commit()
        for key in keys:
            text1 = "insert into " + self.db.SSH_KEY_TABLE.name + " (member_id"
            text2 = ") values ('" + uid
            for col, val in key.iteritems():
                text1 += ", " + col
                text2 += "', '" + val
            sql = text1 + text2 + "');"
            session.execute(sql)
            session.commit()
