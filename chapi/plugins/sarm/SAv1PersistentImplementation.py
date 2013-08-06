from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from chapi.Exceptions import *
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from chapi.SliceAuthority import SAv1DelegateBase

# Utility functions for morphing from native schema to public-facing
# schema

def from_project_urn(project_urn):
    parts = project_urn.split('+')
    return parts[len(parts)-1]

def to_project_urn(authority, project_name):
    return "urn:publicid:IDN+%s+project+%s" % \
        (authority, project_name)

def row_to_project_urn(row):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return to_project_urn(authority, row.project_name)


# Implementation of SA that speaks to GPO Slice and projects table schema
class SAv1PersistentImplementation(SAv1DelegateBase):

    version_number = "1.0"

    services = ["SLICE", "PROJECT", "SLICE_MEMBER", "PROJECT_MEMBER", "SLIVER_INFO"]

    credential_types = ["SFA", "ABAC"]

    # The externally visible data schema for slices
    fields = {
        "SLICE_URN": {"TYPE": "URN"},
        "SLICE_UID": {"TYPE": "UID"},
        "SLICE_NAME": {"TYPE": "STRING", "CREATE": "REQUIRED"},
        "SLICE_DESCRIPTION": {"TYPE": "STRING", "CREATE": "ALLOWED", "UPDATE": True},
        "PROJECT_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False},
        "SLICE_EXPIRATION": {"TYPE": "DATETIME", "UPDATE": True},
        "SLICE_EXPIRED": {"TYPE": "BOOLEAN"},
        "SLICE_CREATION": {"TYPE": "DATETIME"},
        "SLICE_EMAIL": {"TYPE": "EMAIL", "CREATE": "REQUIRED", "UPDATE": True},

        }

    # Mapping from external to internal data schema
    field_mapping = {
        "SLICE_URN" : "slice_urn",
        "SLICE_UID" : "slice_id",
        "SLICE_NAME" : "slice_name",
        "SLICE_DESCRIPTION" :  "slice_description",
        "SLICE_EXPIRATION" :  "expiration",
        "SLICE_EXPIRED" :  "expired",
        "SLICE_CREATION" :  "creation",
        "SLICE_EMAIL" : "slice_email",
        "PROJECT_URN" : row_to_project_urn
        }



    def __init__(self):
        self.config = pm.getService('config')
        self.db_url_filename = self.config.get('chrm.db_url_filename')
        self.authority = self.config.get("chrm.authority")
        self.db_url = open(self.db_url_filename).read()
        self.db = create_engine(self.db_url)
        self.session_class = sessionmaker(bind=self.db)
        self.metadata = MetaData(self.db)


        self.SLICE_TABLE = Table('sa_slice', self.metadata, autoload=True)
        self.SLICE_MEMBER_TABLE = \
            Table('sa_slice_member', self.metadata, autoload=True)
        self.PROJECT_TABLE = Table('pa_project', self.metadata, autoload=True)
        self.PROJECT_MEMBER_TABLE = \
            Table('pa_project_member', self.metadata, autoload=True)
        self.MEMBER_ATTRIBUTE_TABLE = \
            Table('ma_member_attribute', self.metadata, autoload=True)
        self.ROLE_TABLE = Table('cs_attribute', self.metadata, autoload=True)

    def get_version(self):
        version_info = {"VERSION" : self.version_number, 
                        "SERVICES" : self.services,
                        "CREDENTIAL_TYPES" : self.credential_types, 
                        "FIELDS": self.fields}
        return self._successReturn(version_info)

    def lookup_slices(self, client_cert, credentials, options):

        selected_columns, match_criteria = \
            unpack_query_options(options, self.field_mapping)
        session = self.session_class()
        q = session.query(self.SLICE_TABLE, self.PROJECT_TABLE.c.project_id, self.PROJECT_TABLE.c.project_name)
        q = q.filter(self.SLICE_TABLE.c.project_id == self.PROJECT_TABLE.c.project_id)
        q = add_filters(q, match_criteria, self.SLICE_TABLE, self.field_mapping)
#        print "Q = " + str(q)
        rows = q.all()
        session.close()

        slices = {}
        for row in rows:
            slice_urn = row.slice_urn
            result_row = \
                construct_result_row(row, selected_columns, self.field_mapping)
            slices[slice_urn] = result_row
        return self._successReturn(slices)


    def lookup_slice_members(self, \
                                 client_cert, slice_urn, credentials, options):

        session = self.session_class()
        q = session.query(self.SLICE_MEMBER_TABLE, 
                          self.SLICE_TABLE.c.slice_urn,
                          self.MEMBER_ATTRIBUTE_TABLE.c.value,
                          self.ROLE_TABLE.c.name)
        q = q.filter(self.SLICE_TABLE.c.expired == 'f')
        q = q.filter(self.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.SLICE_MEMBER_TABLE.c.slice_id == self.SLICE_TABLE.c.slice_id)
        q = q.filter(self.MEMBER_ATTRIBUTE_TABLE.c.name=='urn')
        q = q.filter(self.SLICE_MEMBER_TABLE.c.member_id == self.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.SLICE_MEMBER_TABLE.c.role == self.ROLE_TABLE.c.id)

#        print "Q = " + str(q)
        rows = q.all()

        members = []
        for row in rows:
            member = {"SLICE_ROLE" : row.name, "SLICE_MEMBER": row.value}
            members.append(member)

        return self._successReturn(members)

    def lookup_slices_for_member(self, \
                                     client_cert, member_urn, \
                                     credentials, options):
        raise CHAPIv1NotImplementedError('')








    
