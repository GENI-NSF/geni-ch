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

import SA_constants as SA
import os
from sqlalchemy import *
from chapi.Exceptions import *
import chapi.Parameters
import amsoil.core.pluginmanager as pm
from chapi.SliceAuthority import SAv1DelegateBase
import sfa.trust.gid as gid
import geni.util.cred_util as cred_util
import geni.util.cert_util as cert_util
from sqlalchemy.orm import mapper
import datetime
from dateutil.relativedelta import relativedelta
import uuid
from tools.dbutils import *
from tools.cert_utils import *
from tools.geni_constants import *
from tools.geni_utils import *
from tools.cs_utils import *
from syslog import syslog

# classes for mapping to sql tables

class Slice(object):
    pass

class Project(object):
    pass

class SliceMember(object):
    pass

class ProjectMember(object):
    pass

class SliverInfo(object):
    pass

# Implementation of SA that speaks to GPO Slice and projects table schema
class SAv1PersistentImplementation(SAv1DelegateBase):

    def __init__(self):
        super(SAv1PersistentImplementation, self).__init__()
        self.db = pm.getService('chdbengine')
        self.config = pm.getService('config')
        self.cert = self.config.get('chapi.sa_cert')
        self.key = self.config.get('chapi.sa_key')

        self.logging_service = pm.getService('loggingv1handler')

        self.trusted_root = self.config.get('chapiv1rpc.ch_cert_root')

        self.trusted_root_files = \
            [os.path.join(self.trusted_root, f) \
                 for f in os.listdir(self.trusted_root) if not f.startswith('CAT')]
#        print "TR = " + str(self.trusted_root_files)

        mapper(Slice, self.db.SLICE_TABLE)
        mapper(SliceMember, self.db.SLICE_MEMBER_TABLE)
        mapper(Project, self.db.PROJECT_TABLE)
        mapper(ProjectMember, self.db.PROJECT_MEMBER_TABLE)
        mapper(SliverInfo, self.db.SLIVER_INFO_TABLE)

    def get_version(self):
        version_info = {"VERSION" : chapi.Parameters.VERSION_NUMBER, 
                        "SERVICES" : SA.services,
                        "CREDENTIAL_TYPES" : SA.credential_types, 
                        "FIELDS": SA.supplemental_fields}
        return self._successReturn(version_info)

    def get_expiration_query(self, session, type, old_flag, resurrect):
        if type == 'slice':
            table = Slice
            q = session.query(Slice.slice_id, \
                                  Slice.project_id, \
                                  Slice.slice_name)
        else:
            table = Project
            q = session.query(Project.project_id, \
                                  Project.project_name)
        q = q.filter(table.expired == old_flag)
        if resurrect:
            q = q.filter(table.expiration > datetime.datetime.utcnow())
        else:
            q = q.filter(table.expiration < datetime.datetime.utcnow())

        return q



    def update_expirations(self, client_uuid, type, resurrect):
        if resurrect:
            old_flag = True
            new_flag = False
            label = "Restored previously expired "
        else:
            old_flag = False
            new_flag = True
            label = "Expired "

        session = self.db.getSession()
        q = self.get_expiration_query(session, type, old_flag, resurrect)
        rows = q.all()
        session.close()

        if len(rows) > 0:
            session = self.db.getSession()
            q = self.get_expiration_query(session, type, old_flag, resurrect)
            update_fields = {'expired' : new_flag}
            q = q.update(update_fields)
            session.commit()
            session.close()


        for row in rows:
            if type == 'slice':
                name = row.slice_name
                attrs = {"SLICE" : row.slice_id, "PROJECT" : row.project_id}
            else:
                name = row.project_name
                attrs = {"PROJECT" : row.project_id}
            self.logging_service.log_event("%s %s %s" % (label, type, name), 
                                           attrs, client_uuid)


    # Check for
    #   Recently expired slices and set their expired flags to 't'
    def update_slice_expirations(self, client_uuid):
        self.update_expirations(client_uuid, 'slice', False)

    # Check for 
    #   Recently expired projects and set their expired flags to 't'
    #   Recently extended expired projects and set their expired flags to 'f'
    def update_project_expirations(self, client_uuid):
        self.update_expirations(client_uuid, 'project', False)
        self.update_expirations(client_uuid, 'project', True)
        self.update_expirations(client_uuid, 'slice', False)

    def lookup_slices(self, client_cert, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        selected_columns, match_criteria = \
            unpack_query_options(options, SA.slice_field_mapping)
        session = self.db.getSession()

        q = session.query(self.db.SLICE_TABLE, self.db.PROJECT_TABLE.c.project_id, self.db.PROJECT_TABLE.c.project_name)

        q = q.filter(self.db.SLICE_TABLE.c.project_id == self.db.PROJECT_TABLE.c.project_id)

        q = add_filters(q, match_criteria, self.db.SLICE_TABLE, SA.slice_field_mapping)
        rows = q.all()
        session.close()

        # in python 2.7, could do dictionary comprehension !!!!!!!!
        slices = {}
        for row in rows:
            slices[row.slice_urn] = construct_result_row(row, \
                selected_columns, SA.slice_field_mapping)
        return self._successReturn(slices)

    # members in a slice
    def lookup_slice_members(self, client_cert, slice_urn, credentials, options):
        return self.lookup_members(client_cert, self.db.SLICE_TABLE, \
            self.db.SLICE_MEMBER_TABLE, slice_urn, "slice_urn", \
            "slice_id", "SLICE_ROLE", "SLICE_MEMBER", "SLICE_MEMBER_UID")

    # members in a project
    def lookup_project_members(self, client_cert, project_urn, \
                               credentials, options):
        project_name = from_project_urn(project_urn)
        return self.lookup_members(client_cert, self.db.PROJECT_TABLE, \
            self.db.PROJECT_MEMBER_TABLE, project_name, "project_name", \
            "project_id", "PROJECT_ROLE", "PROJECT_MEMBER", \
                                       "PROJECT_MEMBER_UID")

    # shared code for lookup_slice_members() and lookup_project_members()
    def lookup_members(self, client_cert, table, member_table, \
                           name, name_field, \
                           id_field, role_txt, member_txt, member_uid_txt):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

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
#        print str(q)
#        print str(rows)
        session.close()
        members = [{role_txt: row.name, member_txt: row.value, \
                        member_uid_txt : row.member_id} for row in rows]
#        print "MEMBERS = " + str(members)
        return self._successReturn(members)

    def lookup_slices_for_member(self, client_cert, member_urn, \
                                 credentials, options):
        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        rows = self.lookup_for_member(member_urn, self.db.SLICE_TABLE, \
                  self.db.SLICE_MEMBER_TABLE, "slice_urn", "slice_id")
        slices = [{"SLICE_ROLE" : row.name, \
                       "SLICE_UID" : row.slice_id, \
                       "SLICE_URN": row.slice_urn} \
                  for row in rows]
        return self._successReturn(slices)

    def get_credentials(self, client_cert, slice_urn, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

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
        ret = extra.copy()
        for k, v in field_mapping.iteritems():
            if not isinstance(v, types.FunctionType) and getattr(object, v):
                ret[k] = getattr(object, v)
        session.add(object)
        session.commit()
        session.close()
        return self._successReturn(ret)

    # create a new slice
    def create_slice(self, client_cert, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()

        # check that slice does not already exist
        name = options["fields"]["SLICE_NAME"]
        if self.get_slice_id(session, "slice_name", name):
            session.close()
            raise CHAPIv1DuplicateError('Already exists a slice named ' + name)

        # Create email if not provided
        if not 'SLICE_EMAIL' in options or not options['SLICE_EMAIL']:
            options['SLICE_EMAIL'] = 'slice-%s@example.com' % name

        # fill in the fields of the object
        slice = Slice()
        project_urn = None
        slice.email = options['SLICE_EMAIL']
        for key, value in options["fields"].iteritems():
            if key == "SLICE_PROJECT_URN":
                project_urn = value
                project_name = from_project_urn(value)
                slice.project_id = self.get_project_id(session, \
                                      "project_name", project_name)
                if not slice.project_id:
                    session.close()
                    raise CHAPIv1ArgumentError('No project with urn ' + value)
            else:
                setattr(slice, SA.slice_field_mapping[key], value)
        slice.creation = datetime.datetime.utcnow()
        if not slice.expiration:
            slice.expiration = slice.creation + relativedelta(days=7)
        slice.slice_id = str(uuid.uuid4())
        slice.owner_id = client_uuid
        slice.slice_urn = urn_for_slice(slice.slice_name, project_name)
        cert, k = cert_util.create_cert(slice.slice_urn, \
            issuer_key = self.key, issuer_cert = self.cert, \
            lifeDays = (slice.expiration - slice.creation).days + 1, \
            email = slice.slice_email, uuidarg=slice.slice_id)
        slice.certificate = cert.save_to_string()

        # Add slice lead member
        ins = self.db.SLICE_MEMBER_TABLE.insert().values(slice_id=slice.slice_id, member_id = client_uuid, role = LEAD_ATTRIBUTE) 
        result = session.execute(ins)

        # Keep assertions synchronized with membership
        add_attribute(self.db, session, client_uuid, client_uuid, \
                          LEAD_ATTRIBUTE, SLICE_CONTEXT, slice.slice_id)

        # Add project lead as member (if not same)
        project_lead_uuid = None
        lookup_result = self.lookup_project_members(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        {})
        if lookup_result['code'] != NO_ERROR:
            return lookup_result
        for row in lookup_result['value']:
            if row['PROJECT_ROLE'] == LEAD_ATTRIBUTE:
                project_lead_uuid = row['MEMBER_UID']
                break

        if project_lead_uuid != client_uuid:
            ins = self.db.SLICE_MEMBER_TABLE.insert().values(slice_id=slice.slice_id, member_id = project_lead_uuid, role=MEMBER_ATTRIBUTE)
            result = session.execute(ins)
            # Keep assertions synchronized with membership
            add_attribute(self.db, session, client_uuid, project_lead_uuid, \
                              MEMBER_ATTRIBUTE, SLICE_CONTEXT, slice.slice_id)


        attribs = {"SLICE" : slice.slice_id, "PROJECT" : slice.project_id}
        self.logging_service.log_event("Created slice " + name, 
                                       attribs, client_uuid)

        # do the database write
        return self.finish_create(session, slice, SA.slice_field_mapping)

    # update an existing slice
    def update_slice(self, client_cert, slice_urn, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        if not self.get_slice_id(session, "slice_urn", slice_urn):
            session.close()
            raise CHAPIv1ArgumentError('No slice with urn ' + slice_urn)
        q = session.query(Slice)
        q = q.filter(getattr(Slice, "slice_urn") == slice_urn)
        updates = {}
        for field, value in options['fields'].iteritems():
            updates[SA.slice_field_mapping[field]] = value
        q = q.update(updates)
        session.commit()
        session.close()

        # Log the update project
        client_uuid = get_uuid_from_cert(client_cert)
        slice_uuid = \
            self.get_slice_id(session, 'slice_urn', slice_urn)
        project_name, authority, slice_name = \
            extract_data_from_slice_urn(slice_urn)
        project_uuid = \
            self.get_project_id(session, 'project_name', project_name)
        attribs = {"PROJECT" : project_uuid, "SLICE" : slice_uuid}
        self.logging_service.log_event("Updated slice " + slice_name, 
                                       attribs, client_uuid)
        if "SLICE_EXPIRATION" in options['fields']: 
            expiration = options['fields']['SLICE_EXPIRATION']
            self.logging_service.log_event("Renewed slice %s until %s" % \
                                               (slice_name, expiration), \
                                               attribs, client_uuid)


        return self._successReturn(True)

    # create a new project
    def create_project(self, client_cert, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()

        # check that project does not already exist
        name = options["fields"]["PROJECT_NAME"]
        if self.get_project_id(session, "project_name", name):
            session.close()
            raise CHAPIv1DuplicateError('Already exists a project named ' + name)

        # fill in the fields of the object
        project = Project()
        for key, value in options["fields"].iteritems():
            setattr(project, SA.project_field_mapping[key], value)
        project.creation = datetime.datetime.utcnow()
        if project.expiration == "": project.expiration=None
        project.project_id = str(uuid.uuid4())

        if not hasattr(project, 'project_email') or not project.project_email:
            email = "project-%s@example.com" % name
            setattr(project, 'project_email', email)

        # Set the project lead (the creator)
        if not hasattr(project, 'lead_id') or not project.lead_id:
            setattr(project, 'lead_id', client_uuid)

        # Add project lead member to member table and assertion table
        ins = self.db.PROJECT_MEMBER_TABLE.insert().values(\
            project_id=project.project_id, \
                member_id = client_uuid, \
                role = LEAD_ATTRIBUTE) 
        result = session.execute(ins)

        # Keep assertions synchronized with membership
        add_attribute(self.db, session, client_uuid, client_uuid, \
                          LEAD_ATTRIBUTE, \
                          PROJECT_CONTEXT, project.project_id)

        attribs = {"PROJECT" : project.project_id}
        self.logging_service.log_event("Created project " + name, 
                                       attribs, client_uuid)


        # do the database write
        return self.finish_create(session, project,  SA.project_field_mapping, \
                        {"PROJECT_URN": row_to_project_urn(project)})

    # update an existing project
    def update_project(self, client_cert, project_urn, credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()
        name = from_project_urn(project_urn)
        if not self.get_project_id(session, "project_name", name):
            session.close()
            raise CHAPIv1ArgumentError('No project with urn ' + project_urn)
        q = session.query(Project)
        q = q.filter(getattr(Project, "project_name") == name)
        updates = {}
        for field, value in options['fields'].iteritems():
            updates[SA.project_field_mapping[field]] = value
        q = q.update(updates)
        session.commit()
        session.close()

        # Log the update project
        client_uuid = get_uuid_from_cert(client_cert)
        project_uuid = \
            self.get_project_id(session, 'project_name', project_name)
        attribs = {"PROJECT" : project_uuid}
        self.logging_service.log_event("Updated project " + name, 
                                       attribs, client_uuid)

        return self._successReturn(True)

    # get info on a set of projects
    def lookup_projects(self, client_cert, credentials, options):
        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        columns, match_criteria = \
            unpack_query_options(options, SA.project_field_mapping)

        session = self.db.getSession()
        q = session.query(self.db.PROJECT_TABLE)
        q = add_filters(q, match_criteria, self.db.PROJECT_TABLE, \
                        SA.project_field_mapping)
        rows = q.all()
        session.close()
        projects = {}
        for row in rows:
            projects[row_to_project_urn(row)] = \
                construct_result_row(row, columns, SA.project_field_mapping)
        return self._successReturn(projects)

    # get the projects associated with a member
    def lookup_projects_for_member(self, client_cert, member_urn, \
                                   credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        rows = self.lookup_for_member(member_urn, self.db.PROJECT_TABLE, \
                  self.db.PROJECT_MEMBER_TABLE, "project_name", "project_id")
        projects = [{"PROJECT_ROLE" : row.name, \
                         "PROJECT_UID" : row.project_id, \
                     "PROJECT_URN": row_to_project_urn(row)} for row in rows]
        return self._successReturn(projects)

    # shared code between projects and slices
    def lookup_for_member(self, member_urn, table, member_table, \
                          name_field, id_field):
        session = self.db.getSession()
        q = session.query(member_table, self.db.MEMBER_ATTRIBUTE_TABLE,
                          table.c[name_field], self.db.ROLE_TABLE.c.name)
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

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()
        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        client_uuid = get_uuid_from_cert(client_cert)
        return self.modify_membership(session, ProjectMember, client_uuid, \
                                          project_id, project_urn, \
                                          options, 'project_id', \
                                          'PROJECT_MEMBER', 'PROJECT_ROLE', \
                                          'project')

    # change the membership in a project
    def modify_slice_membership(self, client_cert, slice_urn, \
                                credentials, options):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        slice_id = self.get_slice_id(session, "slice_urn", slice_urn)
        return self.modify_membership(session, SliceMember, client_uuid, \
                                          slice_id, slice_urn, \
                                          options, 'slice_id', \
                                          'SLICE_MEMBER', 'SLICE_ROLE', \
                                          'slice')

    # shared between modify_slice_membership and modify_project_membership
    def modify_membership(self, session, member_class, client_uuid, id, urn, 
                          options, id_field,
                          member_str, role_str, text_str):
        id_str = '%s.%s' % (member_class.__name__, id_field)

        # first, do the removes
        if 'members_to_remove' in options:
            q = session.query(member_class)
            ids = [self.get_member_id_for_urn(session, m_urn) \
                   for m_urn in options['members_to_remove']]
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
                    raise CHAPIv1DuplicateError('Member ' + \
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


        # Now log the removals, adds, changes

        # Get attributes for logging membership changes
        if text_str == 'slice':
            project_name, authority, slice_name = \
                extract_data_from_slice_urn(urn)
            project_id = \
                self.get_project_id(session, 'project_name', project_name)
            attribs = {"SLICE" : id, "PROJECT_ID" : project_id}
            label = slice_name
        else:
            project_name = get_name_from_urn(urn)
            attribs = {"PROJECT" : id}
            label = project_name

        # Log all removals
        if 'members_to_remove' in options:
            members_to_remove = options['members_to_remove']
            for member_to_remove in members_to_remove:
                member_name = get_name_from_urn(member_to_remove)
                self.logging_service.log_event(
                    "Removed member %s from %s %s" % \
                        (member_name, text_str, label), \
                        attribs, client_uuid)

        # Log all adds
        if 'members_to_add' in options:
            members_to_add = options['members_to_add']
            for member_to_add in members_to_add:
                member_urn = member_to_add[member_str]
                member_name = get_name_from_urn(member_urn)
                member_role = member_to_add[role_str]
                self.logging_service.log_event(
                    "Added member %s in role %s to %s %s" % \
                        (member_name, member_role, text_str, label), 
                        attribs, client_uuid)

        # Log all changes
        if 'members_to_change' in options:
            members_to_change = options['members_to_change']
            for member_to_change in members_to_change:
                member_urn = member_to_change[member_str]
                member_name = get_name_from_urn(member_urn)
                member_role = member_to_change[role_str]
                self.logging_service.log_event(
                    "Changed member %s to role %s to %s %s" % \
                        (member_name, member_role, text_str, label), 
                        attribs, client_uuid)

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

    # Sliver Info API

    def create_sliver_info(self, client_cert, credentials, options):
        session = self.db.getSession()
        sliver = SliverInfo()
        for field, value in options['fields'].iteritems():
           setattr(sliver, SA.sliver_info_field_mapping[field], value)
        if not sliver.creation:
            sliver.creation = datetime.datetime.utcnow()
        if not sliver.expiration:
            sliver.expiration = sliver.creation + relativedelta(days=7)
        return self.finish_create(session, sliver, SA.sliver_info_field_mapping)

    def delete_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options):
        session = self.db.getSession()
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver_urn)
        q.delete(synchronize_session='fetch')
        session.commit()
        session.close()

    def update_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options):
        session = self.db.getSession()
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver_urn)
        vals = {}
        for field, value in options['fields'].iteritems():
           vals[SA.sliver_info_field_mapping[field]] = value
        q.update(vals)
        session.commit()
        session.close()

    def lookup_sliver_info(self, client_cert, credentials, options):
        selected_columns, match_criteria = \
            unpack_query_options(options, SA.sliver_info_field_mapping)
        session = self.db.getSession()
        q = session.query(self.db.SLIVER_INFO_TABLE)
        q = add_filters(q, match_criteria, self.db.SLIVER_INFO_TABLE, \
                        SA.sliver_info_field_mapping)
        rows = q.all()
        session.close()
        slivers = {}
        for row in rows:
            slivers[row.sliver_urn] = \
                construct_result_row(row, columns, SA.sliver_info_field_mapping)
        return self._successReturn(slivers)

#     def register_aggregate(self, client_cert, \
#                                slice_urn, aggregate_url, credentials, options):
#         session = self.db.getSession()
#         agg = Aggregate()
#         agg.slice_urn = slice_urn
#         agg.aggregate_url = aggregate_url
#         session.add(agg)
#         session.commit()
#         session.close()
#         return self._successReturn(None)

#     def remove_aggregate(self, client_cert, \
#                              slice_urn, aggregate_url, credentials, options):
#         session = self.db.getSession()
#         q = session.query(Aggregate)
#         q = q.filter(Aggregate.slice_urn == slice_urn)
#         q = q.filter(Aggregate.aggregate_url == aggregate_url)
#         q.delete()
#         session.commit()
#         session.close()
#         return self._successReturn(None)

#     def lookup_slice_aggregates(self, client_cert, \
#                            slice_urn, credentials, options):
#         session = self.db.getSession()
#         q = session.query(Aggregate.aggregate_url)
#         q = q.filter(Aggregate.slice_urn == slice_urn)
#         rows = q.all()
#         aggs = [row.aggregate_url for row in rows]
#         session.close()
#         return self._successReturn(aggs)

    # Methods for managing pending project requests

    def create_request(self, client_cert, context_type, \
                           context_id, request_type, request_text, \
                           request_details, credentials, options):
        client_uuid = get_uuid_from_cert(client_cert)
        session = self.db.getSession()
        ins = self.db.PROJECT_REQUEST_TABLE.insert().values(
            context_type = context_type, \
                context_id = context_id, \
                request_type = request_type, \
                request_text = request_text, \
                request_details = request_details, \
                creation_timestamp = datetime.datetime.utcnow(), \
                status = PENDING_STATUS, \
                requestor = client_uuid)
        result = session.execute(ins)
        
        query = "select max(id) from pa_project_member_request"
        request_id  = session.execute(query).fetchone().values()[0]
        session.commit()
        session.close()
        return self._successReturn(request_id)

    def resolve_pending_request(self, client_cert, context_type, request_id, \
                                    resolution_status, resolution_description,  \
                                    credentials, options):
        client_uuid = get_uuid_from_cert(client_cert)
        session = self.db.getSession()

        update_values = {'status' : resolution_status, 
                         'resolver' : client_uuid, 
                         'resolution_description' : resolution_description,
                         'resolution_timestamp' : datetime.datetime.utcnow() 
                         }
        update = self.db.PROJECT_REQUEST_TABLE.update(values=update_values)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        session.execute(update)
        session.commit()
        session.close()
        return self._successReturn(True)

    def get_requests_for_context(self, client_cert, context_type, \
                                 context_id, status, \
                                 credentials, options):
        session = self.db.getSession()
        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        if status:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == status)
        rows = q.all()
        session.close()
        result = [construct_result_row(row, SA.project_request_columns, 
                                       SA.project_request_field_mapping) \
                      for row in rows]
        return self._successReturn(result)

    def get_requests_by_user(self, client_cert, member_id, context_type, \
                                 context_id, status, \
                                 credentials, options):
        session = self.db.getSession()
        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        if context_id:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        if status or status == 0:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == status)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.requestor == member_id)

        rows = q.all()
        session.close()
#        print "ROWS = " + str(rows)
        result = [construct_result_row(row, SA.project_request_columns, \
                                           SA.project_request_field_mapping) \
                      for row in rows]
        return self._successReturn(result)

    def get_pending_requests_for_user(self, client_cert, member_id, \
                                          context_type, context_id, \
                                          credentials, options):
        session = self.db.getSession()
        # Filter those projects with pending requsts to those for which
        # Given member is lead or admin
        q = session.query(self.db.PROJECT_REQUEST_TABLE, self.db.PROJECT_MEMBER_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == self.db.PROJECT_MEMBER_TABLE.c.project_id)
        q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.member_id == member_id)
        q = q.filter(self.db.PROJECT_MEMBER_TABLE.c.role.in_([LEAD_ATTRIBUTE, ADMIN_ATTRIBUTE]))
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        if context_id:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == PENDING_STATUS)
        rows = q.all()
        session.close()
#        print "ROWS = " + str(rows)
        result = [construct_result_row(row, SA.project_request_columns, \
                                           SA.project_request_field_mapping) \
                      for row in rows]
        return self._successReturn(result)

    def get_number_of_pending_requests_for_user(self, client_cert, member_id, \
                                                    context_type, context_id, \
                                                    credentials, options):
        requests = self.get_pending_requests_for_user(client_cert, member_id, \
                                                          context_type, context_id,  \
                                                          credentials, options)
        if requests['code'] != NO_ERROR:
            return requests
        return self._successReturn(len(requests['value']))

    def get_request_by_id(self, client_cert, request_id, context_type, \
                              credentials, options):
        session = self.db.getSession()
        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        rows = q.all()
        session.close()
        if len(rows) == 0:
            return self._successReturn(None)
        return self._successReturn(construct_result_row(rows[0], \
            SA.project_request_columns, SA.project_request_field_mapping))

