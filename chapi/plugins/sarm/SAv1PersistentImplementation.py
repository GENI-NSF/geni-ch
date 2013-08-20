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

import os
from sqlalchemy import *
from chapi.Exceptions import *
import amsoil.core.pluginmanager as pm
from tools.dbutils import *
from chapi.SliceAuthority import SAv1DelegateBase
import sfa.trust.gid as gid
import geni.util.cred_util as cred_util
import geni.util.cert_util as cert_util
from sqlalchemy.orm import mapper
from datetime import *
from dateutil.relativedelta import relativedelta
import uuid


# Utility functions for morphing from native schema to public-facing
# schema

# Turn a project URN into a project name
def from_project_urn(project_urn):
    parts = project_urn.split('+')
    return parts[len(parts)-1]

# Turn a project name into a project URN
def to_project_urn(authority, project_name):
    return "urn:publicid:IDN+%s+project+%s" % \
        (authority, project_name)

# Turn a row with project name into a project URN
def row_to_project_urn(row):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return to_project_urn(authority, row.project_name)

def urn_for_slice(slice_name, project_name):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return "urn:publicid:IDN+%s:%s+project+%s" % \
        (authority, project_name, slice_name)

# classes for mapping to sql tables

class Slice(object):
    pass

class Project(object):
    pass

class SliceMember(object):
    pass

class ProjectMember(object):
    pass


# Implementation of SA that speaks to GPO Slice and projects table schema
class SAv1PersistentImplementation(SAv1DelegateBase):

    version_number = "1.0"

    services = ["SLICE", "PROJECT", "SLICE_MEMBER", "PROJECT_MEMBER", "SLIVER_INFO"]

    credential_types = ["SFA", "ABAC"]

    # The externally visible data schema for slices
    slice_mandatory_fields  = {
        "SLICE_URN": {"TYPE": "URN"},
        "SLICE_UID": {"TYPE": "UID"},
        "SLICE_NAME": {"TYPE": "STRING", "CREATE": "REQUIRED"},
        "SLICE_DESCRIPTION": {"TYPE": "STRING", "CREATE": "ALLOWED", "UPDATE": True},
        "SLICE_EXPIRATION": {"TYPE": "DATETIME", "CREATE" : "ALLOWED", "UPDATE": True},
        "SLICE_EXPIRED": {"TYPE": "BOOLEAN"},
        "SLICE_CREATION": {"TYPE": "DATETIME"},
        }

    slice_supplemental_fields = {
        "SLICE_OWNER" : {"TYPE" : "UUID", "UPDATE" : True},
        "SLICE_EMAIL": {"TYPE": "EMAIL", "CREATE": "REQUIRED", "UPDATE": True},
        "PROJECT_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False}
    }

    project_mandatory_fields = {
        "PROJECT_URN" : {"TYPE" : "URN"},
        "PROJECT_UID" : {"TYPE" : "UID"},
        "PROJECT_NAME" : {"TYPE" : "STRING", "CREATE" : "REQUIRED"},
        "PROJECT_DESCRIPTION" : {"TYPE" : "STRING", "CREATE" : "ALLOWED", "UPDATE" : True},
        "PROJECT_EXPIRATION" : {"TYPE" : "DATETIME", "CREATE" : "ALLOWED", "UPDATE" : True},
        "PROJECT_EXPIRED" : {"TYPE" : "BOOLEAN"},
        "PROJECT_CREATION" : {"TYPE" : "DATETIME"},
        }

    project_supplemental_fields = {
        "PROJECT_EMAIL": {"TYPE": "EMAIL", "CREATE": "REQUIRED", "UPDATE": True, "OBJECT" : "PROJECT"}
        }

    # Mapping from external to internal data schema (SLICE)
    slice_field_mapping = {
        "SLICE_URN" : "slice_urn",
        "SLICE_UID" : "slice_id",
        "SLICE_NAME" : "slice_name",
        "SLICE_DESCRIPTION" :  "slice_description",
        "SLICE_EXPIRATION" :  "expiration",
        "SLICE_EXPIRED" :  "expired",
        "SLICE_CREATION" :  "creation",
        "SLICE_EMAIL" : "slice_email",
        "SLICE_OWNER" : "owner_id", 
        "PROJECT_URN" : row_to_project_urn
        }

    # Mapping from external to internal data schema (PROJECT)
    project_field_mapping = {
        "PROJECT_URN" : row_to_project_urn,
        "PROJECT_UID" : "project_id",
        "PROJECT_NAME" : "project_name",
        "PROJECT_DESCRPTION" : "project_purpose",
        "PROJECT_EXPIRATION" : "expiration",
        "PROJECT_EXPIRED" : "expired",
        "PROJECT_CREATION" : "creation",
        "PROJECT_EMAIL" : "project_email"
        }



    def __init__(self):
        self.db = pm.getService('chdbengine')
        self.config = pm.getService('config')
        self.cert = self.config.get('chapiv1rpc.ch_cert')
        self.key = self.config.get('chapiv1rpc.ch_key')

        self.cert = '/usr/share/geni-ch/sa/sa-cert.pem'
        self.key = '/usr/share/geni-ch/sa/sa-key.pem'

        self.trusted_root = self.config.get('chapiv1rpc.ch_cert_root')

        self.trusted_root = '/usr/share/geni-ch/portal/gcf.d/trusted_roots'
        self.trusted_root_files = \
            [os.path.join(self.trusted_root, f) \
                 for f in os.listdir(self.trusted_root) if not f.startswith('CAT')]
#        print "TR = " + str(self.trusted_root_files)

        mapper(Slice, self.db.SLICE_TABLE)
        mapper(SliceMember, self.db.SLICE_MEMBER_TABLE)
        mapper(Project, self.db.PROJECT_TABLE)
        mapper(ProjectMember, self.db.PROJECT_MEMBER_TABLE)


    def get_version(self):
        version_info = {"VERSION" : self.version_number, 
                        "SERVICES" : self.services,
                        "CREDENTIAL_TYPES" : self.credential_types, 
                        "FIELDS": self.supplemental_fields}
        return self._successReturn(version_info)

    def lookup_slices(self, client_cert, credentials, options):

        selected_columns, match_criteria = \
            unpack_query_options(options, self.slice_field_mapping)
        session = self.db.getSession()
        q = session.query(self.db.SLICE_TABLE, self.db.PROJECT_TABLE.c.project_id, self.db.PROJECT_TABLE.c.project_name)
        q = q.filter(self.db.SLICE_TABLE.c.project_id == self.db.PROJECT_TABLE.c.project_id)
        q = add_filters(q, match_criteria, self.db.SLICE_TABLE, self.slice_field_mapping)
#        print "Q = " + str(q)
        rows = q.all()
        session.close()

        slices = {}
        for row in rows:
            slice_urn = row.slice_urn
            result_row = \
                construct_result_row(row, selected_columns, self.slice_field_mapping)
            slices[slice_urn] = result_row
#        print "SLICES = " + str(slices)
        return self._successReturn(slices)


    def lookup_slice_members(self, \
                                 client_cert, slice_urn, credentials, options):

        session = self.db.getSession()
        q = session.query(self.db.SLICE_MEMBER_TABLE, 
                          self.db.SLICE_TABLE.c.slice_urn,
                          self.db.MEMBER_ATTRIBUTE_TABLE.c.value,
                          self.db.ROLE_TABLE.c.name)
        q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
        q = q.filter(self.db.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.slice_id == self.db.SLICE_TABLE.c.slice_id)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name=='urn')
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.member_id == self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.role == self.db.ROLE_TABLE.c.id)

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

        session = self.db.getSession()
        q = session.query(self.db.SLICE_MEMBER_TABLE, 
                          self.db.MEMBER_ATTRIBUTE_TABLE,
                          self.db.SLICE_TABLE.c.slice_urn,
                          self.db.ROLE_TABLE.c.name)
        q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == member_urn)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.member_id == self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.SLICE_TABLE.c.slice_id == self.db.SLICE_MEMBER_TABLE.c.slice_id)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.role == self.db.ROLE_TABLE.c.id)

#        print "Q = " + str(q)
        rows = q.all()

        slices = []
        for row in rows:
            slice = {"SLICE_ROLE" : row.name, "SLICE_URN": row.slice_urn}
            slices.append(slice)

        return self._successReturn(slices)

    def get_credentials(self, client_cert, slice_urn, credentials, options):

        session = self.db.getSession()
        q = session.query(self.db.SLICE_TABLE.c.expiration, \
                              self.db.SLICE_TABLE.c.certificate)
        q = q.filter(self.db.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
        rows = q.all()
        if len(rows) == 0:
            return self._errorReturn("Can't get slice credential " + \
                                         "on expired or non-existent slice %s"\
                                         % slice_urn)

        
        row = rows[0]
        expiration = row.expiration
        user_gid = gid.GID(string=client_cert)
        slice_gid = gid.GID(string=row.certificate)
        delegatable = False
        slice_cred = cred_util.create_credential(user_gid, slice_gid, \
                                                     expiration, 'slice', \
                                                     self.key, self.cert, \
                                                     self.trusted_root_files, \
                                                     delegatable)

        slice_cred_xml = slice_cred.xml

        slice_cred_tuple = \
            {'geni_type' : 'SFA', 'geni_version' : '1', \
                 'geni_value' : slice_cred_xml}
        slice_creds = [slice_cred_tuple]
        return self._successReturn(slice_creds)

    # check whether a slice exists
    def slice_exists(self, session, name):
        q = session.query(Slice)
        q = q.filter(Slice.slice_name == name)
        q = q.filter(Slice.expired == "f")
        return len(q.all()) > 0

    # check whether a project exists
    def get_project_id(self, session, project_name):
        q = session.query(Project.project_id)
        q = q.filter(Project.project_name == project_name)
        rows = q.all()
        if (len(rows) == 0):
            return None
        return rows[0].project_id

    # create a new slice
    def create_slice(self, client_cert, credentials, options):
        session = self.db.getSession()
        if self.slice_exists(session, options["fields"]["SLICE_NAME"]):
            session.close()
            raise CHAPIv1ArgumentError('Already exists a slice named ' + \
                                       options["fields"]["SLICE_NAME"])
        slice = Slice()
        for key, value in options["fields"].iteritems():
            if key == "PROJECT_URN":
                project_name = from_project_urn(value)
                slice.project_id = self.get_project_id(session, project_name)
                if (slice.project_id == None):
                    session.close()
                    raise CHAPIv1ArgumentError('No project with urn ' + value)
            else:
                setattr(slice, self.slice_field_mapping[key], value)
        slice.creation = datetime.now()
        if not slice.expiration:
            slice.expiration = slice.creation + relativedelta(days=7)
        slice.slice_id = str(uuid.uuid4())
        slice.slice_urn = urn_for_slice(slice.slice_name, project_name)
        cert, k = cert_util.create_cert(slice.slice_urn, \
            issuer_key = self.key, issuer_cert = self.cert, \
            lifeDays = (slice.expiration - slice.creation).days, \
            email = slice.slice_email, uuidarg=slice.slice_id)
        slice.certificate = cert.save_to_string()
        session.add(slice)
        session.commit()
        session.close()
        return self._successReturn(True)

    def update_slice(self, slice_urn, credentials, options):
        # *** WRITE ME
        raise CHAPIv1NotImplementedError('')
