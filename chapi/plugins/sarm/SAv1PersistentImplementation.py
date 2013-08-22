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
    return "urn:publicid:IDN+%s:%s+slice+%s" % \
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
        "PROJECT_OWNER" : {"TYPE" : "UUID", "UPDATE" : True},
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
        "PROJECT_DESCRIPTION" : "project_purpose",
        "PROJECT_EXPIRATION" : "expiration",
        "PROJECT_EXPIRED" : "expired",
        "PROJECT_CREATION" : "creation",
        "PROJECT_EMAIL" : "project_email",
        "PROJECT_OWNER" : "lead_id"
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

    # members in a slice
    def lookup_slice_members(self, client_cert, slice_urn, credentials, options):
        return self.lookup_members(self.db.SLICE_TABLE, \
            self.db.SLICE_MEMBER_TABLE, slice_urn, "slice_urn", \
            "slice_id", "SLICE_ROLE", "SLICE_MEMBER")

    # shared code for lookup_slice_members() and lookup_project_members()
    def lookup_members(self, table, member_table, name, name_field, \
                       id_field, role_txt, member_txt):
        session = self.db.getSession()
        q = session.query(member_table, table.c[name_field],
                          self.db.MEMBER_ATTRIBUTE_TABLE.c.value,
                          self.db.ROLE_TABLE.c.name)
        q = q.filter(table.c.expired == 'f')
        q = q.filter(table.c[name_field] == name)
        q = q.filter(member_table.c[id_field] == table.c[id_field])
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(member_table.c.member_id == \
                     self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(member_table.c.role == self.db.ROLE_TABLE.c.id)
        rows = q.all()
        session.close()
        members = [{role_txt: row.name, member_txt: row.value} for row in rows]
        return self._successReturn(members)

    def lookup_slices_for_member(self, client_cert, member_urn, \
                                 credentials, options):
        rows = self.lookup_for_member(member_urn, self.db.SLICE_TABLE, \
                  self.db.SLICE_MEMBER_TABLE, "slice_urn", "slice_id")
        slices = [{"SLICE_ROLE" : row.name, "SLICE_URN": row.slice_urn} \
                  for row in rows]
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

    # check whether a current slice exists, and if so return its id
    def get_slice_id(self, session, field, value):
        q = session.query(Slice.slice_id)
        q = q.filter(getattr(Slice, field) == value)
        q = q.filter(Slice.expired == "f")
        rows = q.all()
        if (len(rows) == 0):
            return None
        return rows[0].slice_id

    # check whether a project exists, and if so return its id
    def get_project_id(self, session, field, value):
        q = session.query(Project.project_id)
        q = q.filter(getattr(Project, field) == value)
        rows = q.all()
        if (len(rows) == 0):
            return None
        return rows[0].project_id

    # shared by create_slice() and create_project()
    def finish_create(self, session, object, field_mapping, extra = {}):
        ret = {k: getattr(object, v) for k, v in field_mapping.iteritems() \
             if not isinstance(v, types.FunctionType) and getattr(object, v)}
        session.add(object)
        session.commit()
        session.close()
        ret.update(extra)
        return self._successReturn(ret)

    # create a new slice
    def create_slice(self, client_cert, credentials, options):
        session = self.db.getSession()

        # check that slice does not already exist
        name = options["fields"]["SLICE_NAME"]
        if self.get_slice_id(session, "slice_name", name):
            session.close()
            raise CHAPIv1ArgumentError('Already exists a slice named ' + name)

        # fill in the fields of the object
        slice = Slice()
        for key, value in options["fields"].iteritems():
            if key == "PROJECT_URN":
                project_name = from_project_urn(value)
                slice.project_id = self.get_project_id(session, \
                                      "project_name", project_name)
                if not slice.project_id:
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
            lifeDays = (slice.expiration - slice.creation).days + 1, \
            email = slice.slice_email, uuidarg=slice.slice_id)
        slice.certificate = cert.save_to_string()

        # do the database write
        return self.finish_create(session, slice, self.slice_field_mapping)

    # update an existing slice
    def update_slice(self, client_cert, slice_urn, credentials, options):
        session = self.db.getSession()
        if not self.get_slice_id(session, "slice_urn", slice_urn):
            session.close()
            raise CHAPIv1ArgumentError('No slice with urn ' + slice_urn)
        q = session.query(Slice)
        q = q.filter(getattr(Slice, "slice_urn") == slice_urn)
        q = q.update({self.slice_field_mapping[field] : value \
                      for field, value in options['fields'].iteritems()})
        session.commit()
        session.close()
        return self._successReturn(True)

    # create a new project
    def create_project(self, client_cert, credentials, options):
        session = self.db.getSession()

        # check that project does not already exist
        name = options["fields"]["PROJECT_NAME"]
        if self.get_project_id(session, "project_name", name):
            session.close()
            raise CHAPIv1ArgumentError('Already exists a project named ' + name)

        # fill in the fields of the object
        project = Project()
        for key, value in options["fields"].iteritems():
            setattr(project, self.project_field_mapping[key], value)
        project.creation = datetime.now()
        if not project.expiration:
            project.expiration = project.creation + relativedelta(days=7)
        project.project_id = str(uuid.uuid4())

        # do the database write
        return self.finish_create(session, project,  self.project_field_mapping, \
                        {"PROJECT_URN": row_to_project_urn(project)})

    # update an existing project
    def update_project(self, client_cert, project_urn, credentials, options):
        session = self.db.getSession()
        name = from_project_urn(project_urn)
        if not self.get_project_id(session, "project_name", name):
            session.close()
            raise CHAPIv1ArgumentError('No project with urn ' + project_urn)
        q = session.query(Project)
        q = q.filter(getattr(Project, "project_name") == name)
        q = q.update({self.project_field_mapping[field] : value \
                      for field, value in options['fields'].iteritems()})
        session.commit()
        session.close()
        return self._successReturn(True)

    # get info on a set of projects
    def lookup_projects(self, client_cert, credentials, options):
        columns, match_criteria = \
            unpack_query_options(options, self.project_field_mapping)
        session = self.db.getSession()
        q = session.query(self.db.PROJECT_TABLE)
        q = add_filters(q, match_criteria, self.db.PROJECT_TABLE, \
                        self.project_field_mapping)
        rows = q.all()
        session.close()
        projects = {row_to_project_urn(row) : \
            construct_result_row(row, columns, self.project_field_mapping) \
            for row in rows}
        return self._successReturn(projects)

    # get the projects associated with a member
    def lookup_projects_for_member(self, client_cert, member_urn, \
                                   credentials, options):
        rows = self.lookup_for_member(member_urn, self.db.PROJECT_TABLE, \
                  self.db.PROJECT_MEMBER_TABLE, "project_name", "project_id")
        projects = [{"PROJECT_ROLE" : row.name, \
                     "PROJECT_URN": row_to_project_urn(row)} for row in rows]
        return self._successReturn(projects)

    # shared code between projects and slices
    def lookup_for_member(self, member_urn, table, member_table, \
                          name_field, id_field):
        session = self.db.getSession()
        q = session.query(member_table, self.db.MEMBER_ATTRIBUTE_TABLE,
                          table.c[name_field], self.db.ROLE_TABLE.c.name)
        q = q.filter(table.c.expired == 'f')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == member_urn)
        q = q.filter(member_table.c.member_id == \
                     self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(table.c[id_field] == member_table.c[id_field])
        q = q.filter(member_table.c.role == self.db.ROLE_TABLE.c.id)
        rows = q.all()
        session.close()
        return rows

    # change the membership in a project
    def modify_project_membership(self, client_cert, project_urn, \
                                  credentials, options):
        session = self.db.getSession()
        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        return self.modify_membership(session, ProjectMember, project_id, \
            options, 'project_id', 'PROJECT_MEMBER', 'PROJECT_ROLE', 'project')

    # change the membership in a project
    def modify_slice_membership(self, client_cert, slice_urn, \
                                credentials, options):
        session = self.db.getSession()
        slice_id = self.get_slice_id(session, "slice_urn", slice_urn)
        return self.modify_membership(session, SliceMember, slice_id, \
            options, 'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

    # shared between modify_slice_membership and modify_project_membership
    def modify_membership(self, session, member_class, id, options, id_field,
                          member_str, role_str, text_str):
        id_str = '%s.%s' % (member_class.__name__, id_field)

        # first, do the removes
        if 'members_to_remove' in options:
            q = session.query(member_class)
            ids = [self.get_member_id_for_urn(session, urn) \
                   for urn in options['members_to_remove']]
            q = q.filter(member_class.member_id.in_(ids))
            q = q.filter(eval(id_str) == id)
            q.delete(synchronize_session='fetch')

        # then, do the additions
        if 'members_to_add' in options:
            for member in options['members_to_add']:
                member_obj = member_class()
                setattr(member_obj, id_field, id)
                member_obj.member_id = self.get_member_id_for_urn \
                                   (session, member[member_str])
                member_obj.role = self.get_role_id(session, member[role_str])
                session.add(member_obj)
                # check that this is not a duplicate
                q = session.query(member_class)
                q = q.filter(eval(id_str) == id)
                q = q.filter(member_class.member_id == member_obj.member_id)
                if len(q.all()) > 1:
                    session.close()
                    raise CHAPIv1ArgumentError('Member ' + \
                        member[member_str] + ' already in ' + text_str)

        # then, the updates
        if 'members_to_change' in options:
            for member in options['members_to_change']:
                q = session.query(member_class)
                q = q.filter(eval(id_str) == id)
                q = q.filter(member_class.member_id == \
                    self.get_member_id_for_urn(session, member[member_str]))
                if len(q.all()) == 0:
                    session.close()
                    raise CHAPIv1ArgumentError('Cannot change member ' + \
                             member[member_str] + ' not in ' + text_str)
                q.update({"role" : self.get_role_id(session, member[role_str])})

        # before committing, check that there is exactly one lead
        q = session.query(member_class)
        q = q.filter(eval(id_str) == id)
        q = q.filter(member_class.role == self.get_role_id(session, "LEAD"))
        num_leads = len(q.all())
        if num_leads != 1:
            session.close()
            raise CHAPIv1ArgumentError('This would result in ' + \
                          str(num_leads) + ' leads for the ' + text_str)

        # finish up
        session.commit()
        session.close()
        return self._successReturn(None)

    def get_member_id_for_urn(self, session, urn):
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == "urn")
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == urn)
        rows = q.all()
        if len(rows) > 0:
           return rows[0].member_id
        return None

    def get_role_id(self, session, role):
        q = session.query(self.db.ROLE_TABLE.c.id)
        q = q.filter(self.db.ROLE_TABLE.c.name == role)
        rows = q.all()
        if len(rows) > 0:
           return rows[0].id
        return None
