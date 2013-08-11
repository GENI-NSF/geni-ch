# Simple persistence-free version of MA for testing/development
from chapi.MemberAuthority import MAv1DelegateBase
from chapi.Exceptions import *
from ext.geni.util.urn_util import URN
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
import ext.sfa.trust.credential as sfa_cred
import ext.sfa.trust.gid as sfa_gid

# Utility functions for morphing from native schema to public-facing
# schema

def urn_to_user_credential(urn):
    cred = sfa_cred.Credential()
    gid = sfa_gid.GID(urn = urn, create = True)
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
#        "MEMBER_SPEAKS_FOR_CREDENTIAL": {"TYPE": "CREDENTIAL"},
        "MEMBER_SSL_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "MEMBER_SSL_PRIVATE_KEY": {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "MEMBER_SSH_PUBLIC_KEY": {"TYPE": "SSH_KEY"},
        "MEMBER_SSH_PRIVATE_KEY": {"TYPE": "SSH_KEY", "PROTECT": "PRIVATE"},
#        "MEMBER_ENABLED": {"TYPE": "BOOLEAN", "UPDATE": True},
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
        "MEMBER_SSH_PUBLIC_KEY": "public_key",
        "MEMBER_SSH_PRIVATE_KEY": "private_key",
        "MEMBER_SSL_PUBLIC_KEY": "certificate",
        "MEMBER_SSL_PRIVATE_KEY": "private_key",
        "USER_CREDENTIAL": urn_to_user_credential
        }

    attributes = ["MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", \
                  "MEMBER_LASTNAME", "MEMBER_USERNAME", "MEMBER_EMAIL", \
                  "MEMBER_DISPLAYNAME", "MEMBER_PHONE_NUMBER", "MEMBER_AFFILIATION"]


    def __init__(self):
        self.db = pm.getService('chdbengine')

    # This call is unprotected: no checking of credentials
    def get_version(self):
        version_info = {"VERSION": self.version_number,
                        "CREDENTIAL_TYPES": self.credential_types,
                        "FIELDS": self.optional_fields}
        return self._successReturn(version_info)

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

    def get_attr_for_uid(self, session, attr, uid):
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == \
                     self.field_mapping[attr])
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == uid)
        rows = q.all()
        return [row.value for row in rows]

    def get_val_for_uid(self, session, table, field, uid):
        q = session.query(table.c[field])
        q = q.filter(table.c.member_id == uid)
        rows = q.all()
        return [eval("row.%s" % field) for row in rows]

    # Common code for answering query
    def lookup_member_info(self, options):
        selected_columns, match_criteria = \
            unpack_query_options(options, self.field_mapping)
        if not match_criteria:
            raise CHAPIv1ArgumentError('Missing a "match" option')
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
                else:
                    if col in self.attributes:
                        vals = self.get_attr_for_uid(session, col, uid)
                    elif col in ["MEMBER_SSH_PUBLIC_KEY", "MEMBER_SSH_PRIVATE_KEY"]:
                        vals = self.get_val_for_uid(session, \
                            self.db.SSH_KEY_TABLE, self.field_mapping[col], uid)
                    else:
                        vals = self.get_val_for_uid(session, \
                            self.db.OUTSIDE_CERT_TABLE, self.field_mapping[col], uid)
                        if not vals:
                            vals = self.get_val_for_uid(session, \
                                self.db.INSIDE_KEY_TABLE, self.field_mapping[col], uid)
                    if vals:
                        values[col] = vals[0]
            members[urn] = values

        session.close()
        return self._successReturn(members)

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, credentials, options):
        print "MAv1DelegateBase.lookup_public_member_info " + \
            "CREDS = %s OPTIONS = %s" % \
            (str(credentials), str(options))
        return self.lookup_member_info(options)

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        return self.lookup_member_info(options)

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        return self.lookup_member_info(options)

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')
