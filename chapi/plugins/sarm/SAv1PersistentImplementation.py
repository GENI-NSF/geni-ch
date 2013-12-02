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

from datetime import datetime
from dateutil.relativedelta import relativedelta
import dateutil.parser
import logging
import os
import re
import uuid
from sqlalchemy import *
from sqlalchemy.orm import mapper

import amsoil.core.pluginmanager as pm

import sfa.trust.gid as gid
from sfa.trust.certificate import Certificate
import geni.util.cred_util as cred_util
import geni.util.cert_util as cert_util
from chapi.Exceptions import *
import chapi.Parameters
from chapi.SliceAuthority import SAv1DelegateBase
import tools.SA_constants as SA
from tools.dbutils import *
from tools.cert_utils import *
from tools.geni_constants import *
from tools.geni_utils import *
from tools.guard_utils import *
from tools.ABACManager import *
from tools.cs_utils import *
from tools.chapi_log import *

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
        method = 'get_version'
#        user_email = get_email_from_cert(self.requestCertificate())
#        chapi_log_invocation(SA_LOG_PREFIX, method, [], {}, {}, {'user': user_email})
        chapi_log_invocation(SA_LOG_PREFIX, method, [], {}, {})

        version_info = {"VERSION" : chapi.Parameters.VERSION_NUMBER, 
                        "SERVICES" : SA.services,
                        "CREDENTIAL_TYPES" : SA.credential_types, 
                        "FIELDS": SA.supplemental_fields}
        result = self._successReturn(version_info)

#        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        chapi_log_result(SA_LOG_PREFIX, method, result)
        return result

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
            q = q.filter(table.expiration > datetime.utcnow())
        else:
            q = q.filter(table.expiration < datetime.utcnow())

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

        if len(rows) > 0:
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
        method = 'lookup_slices'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

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

        result = self._successReturn(slices)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # members in a slice
    def lookup_slice_members(self, client_cert, slice_urn, credentials, options):
        method = 'lookup_slice_members'
        args = {'slice_urn' : slice_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})
        slice_id = None
        if "match" in options:
            if 'SLICE_UID' in options['match']:
                slice_id = options['match']['SLICE_UID']

        if slice_id == None:
            session = self.db.getSession()
            q = session.query(self.db.SLICE_TABLE.c['slice_id'])
            q = q.filter(self.db.SLICE_TABLE.c['slice_urn']==slice_urn)
            q = q.order_by(desc(self.db.SLICE_TABLE.c['creation']))
            rows = q.all()
            slice_id = rows[0][0]
            session.close()

        result = self.lookup_members(client_cert, self.db.SLICE_TABLE, 
                                     self.db.SLICE_MEMBER_TABLE, slice_urn, "slice_urn", 
                                     "slice_id", "SLICE_ROLE", "SLICE_MEMBER", "SLICE_MEMBER_UID",
                                     slice_id)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    # members in a project
    def lookup_project_members(self, client_cert, project_urn, \
                               credentials, options):
        method =  'lookup_project_members'
        args = {'project_urn' : project_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        project_name = from_project_urn(project_urn)
        result = self.lookup_members(client_cert, self.db.PROJECT_TABLE, 
                                     self.db.PROJECT_MEMBER_TABLE, project_name, "project_name", 
                                     "project_id", "PROJECT_ROLE", "PROJECT_MEMBER", 
                                     "PROJECT_MEMBER_UID", None)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    # shared code for lookup_slice_members() and lookup_project_members()
    def lookup_members(self, client_cert, table, member_table, \
                           name, name_field, \
                           id_field, role_txt, member_txt, member_uid_txt, id_value):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        q = session.query(member_table, table.c[name_field],
                          self.db.MEMBER_ATTRIBUTE_TABLE.c.value,
                          self.db.ROLE_TABLE.c.name)
        q = q.filter(table.c[name_field] == name)
        if id_value == None:
            q = q.filter(member_table.c[id_field] == table.c[id_field])
        else:
            q = q.filter(member_table.c[id_field] == id_value)
            q = q.filter(table.c[id_field] == id_value)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(member_table.c.member_id == \
                     self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(member_table.c.role == self.db.ROLE_TABLE.c.id)
        rows = q.all()
        session.close()
        members = [{role_txt: row.name, member_txt: row.value, \
                        member_uid_txt : row.member_id} for row in rows]
        return self._successReturn(members)

    def lookup_slices_for_member(self, client_cert, member_urn, \
                                 credentials, options):
        method = 'lookup_slices_for_member'
        args = {'member_urn' : member_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        rows = self.lookup_for_member(member_urn, self.db.SLICE_TABLE, \
                  self.db.SLICE_MEMBER_TABLE, "slice_urn", "slice_id")
        slices = [{"SLICE_ROLE" : row.name, \
                       "SLICE_UID" : row.slice_id, \
                       "SLICE_URN": row.slice_urn, \
                      "EXPIRED": row.expired } \
                  for row in rows]

        result = self._successReturn(slices)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def get_credentials(self, client_cert, slice_urn, credentials, options):

        method = 'get_credentials'
        args = {'slice_urn' : slice_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        q = session.query(self.db.SLICE_TABLE.c.expiration, \
                              self.db.SLICE_TABLE.c.certificate)
        q = q.filter(self.db.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
        rows = q.all()
        if len(rows) == 0:
            session.close()
            return self._errorReturn("Can't get slice credential " + \
                                         "on expired or non-existent slice %s"\
                                         % slice_urn)

        
        row = rows[0]
        expiration = row.expiration
        # Temporary fix, see ticket #84.
        with open('/usr/share/geni-ch/ma/ma-cert.pem', 'r') as f:
            ma_cert = f.read()
        client_chain = client_cert + ma_cert
        user_gid = gid.GID(string=client_chain)
        slice_gid = gid.GID(string=row.certificate)
        delegatable = False
        slice_cred = cred_util.create_credential(user_gid, slice_gid, \
                                                     expiration, 'slice', \
                                                     self.key, self.cert, \
                                                     self.trusted_root_files, \
                                                     delegatable)

        sfa_raw_creds = [slice_cred.xml]
        abac_raw_creds = []

        q = session.query(self.db.SLICE_MEMBER_TABLE.c.role)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.slice_id == self.db.SLICE_TABLE.c.slice_id)
        q = q.filter(self.db.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.db.SLICE_MEMBER_TABLE.c.member_id == client_uuid)
        rows = q.all()
        session.close()
        if len(rows) > 0:
            row = rows[0]
            role_name = attribute_type_names[row.role]
            slice_role_assertion = "ME.IS_%s_%s<-CALLER" % (role_name, flatten_urn(slice_urn))
#            print "SRA = " + slice_role_assertion
            slice_role_credential = generate_abac_credential(slice_role_assertion, 
                                                              self.cert, self.key, 
                                                              {"CALLER" : client_cert})
                                                              
            abac_raw_creds.append(slice_role_credential)

        sfa_creds = \
            [{'geni_type' : 'geni_sfa', 'geni_version' : 1, 'geni_value' : cred} 
             for cred in sfa_raw_creds]
        abac_creds = \
            [{'geni_type' : 'geni_abac', 'geni_version' : 1, 'geni_value' : cred} 
             for cred in abac_raw_creds]
        creds = sfa_creds + abac_creds

        result = self._successReturn(creds)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    # check whether a current slice exists, and if so return its id
    def get_slice_id(self, session, field, value, include_expired=False):
        rows = self.get_slice_ids(session, field, value, include_expired)
        if (rows is None or len(rows) == 0):
            return None
        else:
            return rows[0]

    def get_slice_ids(self, session, field, value, include_expired=False):
        q = session.query(Slice.slice_id)
        q = q.filter(getattr(Slice, field) == value)
        if not include_expired:
            q = q.filter(Slice.expired == "f")
        q = q.order_by(Slice.expiration.desc()) # first return value will be newest
        rows = q.all()
        if (len(rows) == 0):
            return None
        results = []
        for row in rows:
            results.append(row.slice_id)
        return results

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
        method = 'create_slice'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()

        name = options["fields"]["SLICE_NAME"]

        # FIXME: In old SA we made the slice email be null because FOAM didn't like
        # the fake email addresses

        # Create email if not provided
        if not '_GENI_SLICE_EMAIL' in options['fields'] or \
           not options['fields']['_GENI_SLICE_EMAIL']:
            options['fields']['_GENI_SLICE_EMAIL'] = \
                'slice-%s@example.com' % name

        # fill in the fields of the object
        slice = Slice()
        project_urn = None
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

        # Check if project is not null
        if project_urn == None:
            session.close()
            raise CHAPIv1ArgumentError("No project specified for create_slice");

        # Check if project is not expired, get expiration for later use
        q = session.query(Project.expired, Project.expiration)
        q = q.filter(Project.project_id == slice.project_id)
        project_info = q.one()
        expired = project_info.expired
        project_expiration = project_info.expiration
        if project_info.expired:
            session.close()
            raise CHAPIv1ArgumentError("May not create a slice on expired project");
        
        # Check that slice name is valid
        if ' ' in name:
            session.close()
            raise CHAPIv1ArgumentError('Slice name may not contain spaces.')
        elif len(name) > 19:
            session.close()
            raise CHAPIv1ArgumentError('Slice name %s is too long - use at most 19 characters.' %name)
            
        # FIXME: Externalize this
        pattern = '^[a-zA-Z0-9][a-zA-Z0-9-]{0,18}$'
        valid = re.match(pattern,name)
        if valid == None:
            session.close()
            raise CHAPIv1ArgumentError('Slice name %s is invalid - use at most 19 alphanumeric characters or hyphen. No leading hyphen.' %name)
        # before fill in rest, check that slice does not already exist
        same_name = self.get_slice_ids(session, "slice_name", name)
        if same_name:
            same_project = self.get_slice_ids(session, "project_id",
                                              slice.project_id)
            if same_project and (set(same_name) & set(same_project)):
                session.close()
                raise CHAPIv1DuplicateError('Already exists a slice named ' +
                                            name + ' in project ' + project_name)

        # FIXME: Real slice email

        slice.creation = datetime.utcnow()
        # FIXME: Why check if slice.expiration is set. We are creating the slice here - how can it be set?
        if not slice.expiration:
            # FIXME: Externalize the #7 here
            slice.expiration = slice.creation + relativedelta(days=7)
        else:
            slice.expiration = dateutil.parser.parse(slice.expiration)

        # if project expiration is sooner than slice expiration, use project expiration
        if project_expiration != None and slice.expiration > project_expiration:
            slice.expiration = project_expiration

        slice.slice_id = str(uuid.uuid4())
        slice.owner_id = client_uuid
        slice.slice_urn = urn_for_slice(slice.slice_name, project_name)
        # FIXME: Why is the cert lifeDays 365 days more than the diff between slice expiration and creation?
        cert, k = cert_util.create_cert(slice.slice_urn, \
            issuer_key = self.key, issuer_cert = self.cert, \
            lifeDays = (slice.expiration - slice.creation).days + \
                       SA.SLICE_CERT_LIFETIME, \
            email = slice.slice_email, uuidarg=slice.slice_id)
        slice.certificate = cert.save_to_string()

        # Add slice lead member
        ins = self.db.SLICE_MEMBER_TABLE.insert().values(slice_id=slice.slice_id, member_id = client_uuid, role = LEAD_ATTRIBUTE) 
        result = session.execute(ins)

        # Keep assertions synchronized with membership
        add_attribute(self.db, session, client_uuid, client_uuid, \
                          LEAD_ATTRIBUTE, SLICE_CONTEXT, slice.slice_id)

        # Add project lead and project admins as admin (if not same)
        admins_to_add = []
        members = self.lookup_project_members(client_cert,project_urn, credentials,{})
        if members['code'] != NO_ERROR:
            session.close()
            raise CHAPIv1ArgumentError('No members for project ' + project_urn)
        for member in members['value']:
            if member['PROJECT_ROLE'] == 'ADMIN' or member['PROJECT_ROLE'] == 'LEAD':
                if member['PROJECT_MEMBER_UID'] != client_uuid:
                    admins_to_add.append(member['PROJECT_MEMBER_UID'])
        for admin_uid in admins_to_add:
            ins = self.db.SLICE_MEMBER_TABLE.insert().values(slice_id=slice.slice_id, member_id = admin_uid, role=ADMIN_ATTRIBUTE)
            result = session.execute(ins)
            # Keep assertions synchronized with membership
            add_attribute(self.db, session, client_uuid, admin_uid, \
                              ADMIN_ATTRIBUTE, SLICE_CONTEXT, slice.slice_id)

        attribs = {"SLICE" : slice.slice_id, "PROJECT" : slice.project_id}
        self.logging_service.log_event("Created slice " + name, 
                                       attribs, client_uuid)
        chapi_audit_and_log(SA_LOG_PREFIX, "Created slice " + name + " in project " + slice.project_id, logging.INFO, {'user': user_email})

        # do the database write
        result = self.finish_create(session, slice, SA.slice_field_mapping)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # update an existing slice
    def update_slice(self, client_cert, slice_urn, credentials, options):

        method = 'update_slice'
        args = {'slice_urn' : slice_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        slice_uuid = \
            self.get_slice_id(session, 'slice_urn', slice_urn) # MIK: only non-expired slices
        if not slice_uuid: 
            session.close()
            raise CHAPIv1ArgumentError('No slice with urn ' + slice_urn)
        updates = {}

        project_name, authority, slice_name = \
            extract_data_from_slice_urn(slice_urn)
        project_uuid = \
            self.get_project_id(session, 'project_name', project_name)

        q = session.query(Project.expired, Project.expiration)
        q = q.filter(Project.project_id == project_uuid)
        project_info = q.one()
        project_expiration = project_info.expiration
        if project_info.expired:
            session.close()
            raise CHAPIv1ArgumentError('Cannot update a slice for an expired project')

        q = session.query(Slice.expired, Slice.expiration, Slice.certificate, Slice.slice_email, Slice.slice_id, Slice.creation)
        q = q.filter(Slice.slice_id == slice_uuid)
        slice_info = q.one()
        if slice_info.expired:
            session.close()
            raise CHAPIv1ArgumentError('Cannot update or renew an expired slice')
        slice_expiration = slice_info.expiration
        max_exp = datetime.utcnow() + relativedelta(days=SA.SLICE_MAX_RENEWAL_DAYS)
        new_exp = None # A dateutil for the new slice expiration

        for field, value in options['fields'].iteritems():
            if field=="SLICE_EXPIRATION":
                # convert value to datetime object
                # FIXME: Make it UTC so we compare apples to apples *****
                new_exp = dateutil.parser.parse(value)
#                chapi_debug(SA_LOG_PREFIX, "Slice %s Requested new slice expiration %s" % (slice_name, value)
                # don't renew past project expiration time
                if project_expiration != None and new_exp > project_expiration:
                    if project_expiration < slice_expiration:
                        # Don't reset their request to make it illegal
                        # The error would be surprising
                        value = slice_expiration
                        new_exp = slice_expiration # value just changed from string to datetime
#                        chapi_debug(SA_LOG_PREFIX, "Slice %s Reset renew request %s to project exp %s but that's less than current slice exp %s, so reset to slice exp" % (slice_name, new_exp, project_expiration, slice_expiration))
                    else:
                        value = project_expiration # value just changed from string to datetime
                        new_exp = project_expiration
#                        chapi_debug(SA_LOG_PREFIX, "Slice %s Reset renew request %s to project exp %s" % (slice_name, new_exp, project_expiration))
                # make sure renewal isn't more than max allowed
                if new_exp > max_exp:
                    new_exp = max_exp
                    value = max_exp # value just changed from string to datetime!
#                    chapi_debug(SA_LOG_PREFIX, "Slice %s Reset renew request %s to max exp %s" % (slice_name, new_exp, max_exp))
                # don't shorten slice lifetime
                if slice_expiration > new_exp:
                    session.close()
                    raise CHAPIv1ArgumentError('Cannot shorten slice lifetime')
                # regenerate cert if necessary
                cert = Certificate(string = slice_info.certificate)
                t1 = dateutil.parser.parse(cert.cert.get_notAfter())
                t2 = new_exp
                # FIXME: Why are we assuming the cert's TZ is meant to be that from the input request time. In fact, the input request time should be treated as UTC if not specified, and the TZ in the cert should UTC. Or is a diff between 2 python datetimes something where .days gives you the total days in the diff, in which case we're just losing any hours/minutes.
                t1 = t1.replace(tzinfo = t2.tzinfo)
                if (t1 < t2):
                    t3 = slice_info.creation
                    # FIXME: Note the cert will be good past the slice expiration - why?
                    cert, k = cert_util.create_cert(slice_urn, \
                        issuer_key = self.key, issuer_cert = self.cert, \
                        lifeDays = (t2 - t3).days + SA.SLICE_CERT_LIFETIME, \
                        email = slice_info.slice_email, uuidarg=slice_info.slice_id)
                    updates['certificate'] = cert.save_to_string()
                    
            updates[SA.slice_field_mapping[field]] = value

        q = q.update(updates)
        session.commit()
        session.close()

        # Log the update slice
        client_uuid = get_uuid_from_cert(client_cert)
        attribs = {"PROJECT" : project_uuid, "SLICE" : slice_uuid}
        if "SLICE_EXPIRATION" in options['fields']: 
            # FIXME: Format in RFC3339 format not iso
            self.logging_service.log_event("Renewed slice %s until %s" % \
                                               (slice_name, new_exp.isoformat()), \
                                               attribs, client_uuid)
        else:
            self.logging_service.log_event("Updated slice " + slice_name, 
                                       attribs, client_uuid)

        result = self._successReturn(True)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # create a new project
    def create_project(self, client_cert, credentials, options):

        method = 'create_project'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        name = options["fields"]["PROJECT_NAME"]
        # check that project name is valid
        if ' ' in name:
            raise CHAPIv1ArgumentError('Project name may not contain spaces.')
        elif len(name) > 32:
            raise CHAPIv1ArgumentError('Project name %s is too long - use at most 32 characters.' %name)
            
        # FIXME: Put this in a constants file
        pattern = '^[a-zA-Z0-9][a-zA-Z0-9-_]{0,31}$'
        valid = re.match(pattern,name)
        if valid == None:
            raise CHAPIv1ArgumentError('Project name %s is invalid - use at most 32 alphanumeric characters or hyphen or underscore. No leading hyphen or underscore.' %name)
        
        session = self.db.getSession()

        # check that project does not already exist
        if self.get_project_id(session, "project_name", name):
            session.close()
            raise CHAPIv1DuplicateError('Already exists a project named ' + name)

        # fill in the fields of the object
        project = Project()
        for key, value in options["fields"].iteritems():
            setattr(project, SA.project_field_mapping[key], value)
        project.creation = datetime.utcnow()
        # FIXME: Must project expiration be in UTC?
        if project.expiration == "": project.expiration=None
        project.project_id = str(uuid.uuid4())

        # FIXME: Real project email!
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
        # FIXME: Get the name of the project lead and add this to the log/audit messages
        self.logging_service.log_event("Created project " + name, 
                                       attribs, client_uuid)
        chapi_audit_and_log(SA_LOG_PREFIX, "Created project " + name, logging.INFO, {'user': user_email})

        # FIXME: Email the admins that the project was created

        # do the database write
        result = self.finish_create(session, project,  SA.project_field_mapping, \
                                        {"PROJECT_URN": row_to_project_urn(project)})

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # update an existing project
    def update_project(self, client_cert, project_urn, credentials, options):
        method = 'update_project'
        args = {'project_urn' : project_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})


        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()
        name = from_project_urn(project_urn)
        project_uuid = self.get_project_id(session, 'project_name', name)
        if not project_uuid:
            session.close()
            raise CHAPIv1ArgumentError('No project with urn ' + project_urn)
        q = session.query(Project)
        q = q.filter(getattr(Project, "project_name") == name)
        updates = {}
        # Handle empty string for no expiration
        if (options['fields'].has_key('PROJECT_EXPIRATION')
            and not options['fields']['PROJECT_EXPIRATION']):
            options['fields']['PROJECT_EXPIRATION'] = None

        # FIXME: Are there any rules on TZ for project expiration?

        for field, value in options['fields'].iteritems():
            updates[SA.project_field_mapping[field]] = value
        q = q.update(updates)
        session.commit()
        session.close()

        # Log the update project
        client_uuid = get_uuid_from_cert(client_cert)
        attribs = {"PROJECT" : project_uuid}
        # FIXME: Say what was updated
        self.logging_service.log_event("Updated project " + name, 
                                       attribs, client_uuid)

        result =self._successReturn(True)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # get info on a set of projects
    def lookup_projects(self, client_cert, credentials, options):

        method = 'lookup_projects'
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, {}, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        columns, match_criteria = \
            unpack_query_options(options, SA.project_field_mapping)

        if match_criteria.has_key('PROJECT_URN'):
            urns = match_criteria['PROJECT_URN']
            del match_criteria['PROJECT_URN']
            if not isinstance(urns, list):
                urns = [urns]
            match_criteria['PROJECT_NAME'] = \
                [from_project_urn(urn) for urn in urns]

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
        result = self._successReturn(projects)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # get the projects associated with a member
    def lookup_projects_for_member(self, client_cert, member_urn, \
                                   credentials, options):

        method = 'lookup_projects_for_member'
        args = {'member_urn' : member_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        rows = self.lookup_for_member(member_urn, self.db.PROJECT_TABLE, \
                  self.db.PROJECT_MEMBER_TABLE, "project_name", "project_id")
        projects = [{"PROJECT_ROLE" : row.name, \
                         "PROJECT_UID" : row.project_id, \
                         "PROJECT_URN": row_to_project_urn(row), \
                         "EXPIRED" : row.expired } \
                        for row in rows]
        result = self._successReturn(projects)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # shared code between projects and slices
    def lookup_for_member(self, member_urn, table, member_table, \
                          name_field, id_field):
        session = self.db.getSession()
        q = session.query(member_table, self.db.MEMBER_ATTRIBUTE_TABLE,
                          table.c[name_field], self.db.ROLE_TABLE.c.name, table.c['expired'])
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

        method = 'modify_project_membership'
        args = {'project_urn' : project_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})
        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()
        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        old_project_lead = self.get_project_lead(session, project_id)
        new_project_lead = old_project_lead;
        old_lead_urn = self.get_member_urn_for_id(session, old_project_lead)
        client_uuid = get_uuid_from_cert(client_cert)

        # If we are removing the lead, make sure there is an authorized admin on the project
        #   If yes, make the admin be the lead, and the current lead be an admin
        #   If no, FAIL

        if 'members_to_remove' in options:
            for member in options['members_to_remove']:
                if (member==old_lead_urn):
                    lookup_result = self.lookup_project_members(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        {})
                    if lookup_result['code'] != NO_ERROR:
                        session.close()
                        return lookup_result   # Shouldn't happen: Should raise an exception
                    new_lead_urn = None
                    for row in lookup_result['value']:
                        if row['PROJECT_ROLE'] == 'ADMIN':
                            # check if admin has lead privileges
                            q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value).\
                                filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == row['PROJECT_MEMBER_UID']). \
                                filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
                            rows = q.all()
                            if len(rows) == 0 or rows[0][0] != 'true':
                                continue
                            new_project_lead = row['PROJECT_MEMBER_UID']
                            new_lead_urn = self.get_member_urn_for_id(session, new_project_lead)
                            
                            role_options = {'members_to_change': [{'PROJECT_MEMBER': old_lead_urn, 'PROJECT_ROLE': 'ADMIN'},{'PROJECT_MEMBER': new_lead_urn, 'PROJECT_ROLE': 'LEAD'}]}
                            result = self.modify_membership(session, ProjectMember, client_uuid, \
                                                                project_id, project_urn, \
                                                                role_options, 'project_id', \
                                                                'PROJECT_MEMBER', 'PROJECT_ROLE', \
                                                                'project')

                            break
                    if new_lead_urn==None:
                        session.close()
                        raise CHAPIv1ArgumentError('New project lead not authorized')
                    
        if 'members_to_change' in options:
            # if project lead will change, make sure new project lead authorized
            for change in options['members_to_change']:
                if change['PROJECT_ROLE'] == 'LEAD':
                    lookup_result = self.lookup_project_members(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        {})
                    if lookup_result['code'] != NO_ERROR:
                        session.close()
                        return lookup_result   # Shouldn't happen: Should raise an exception
                    new_lead_urn = change['PROJECT_MEMBER']
                    for row in lookup_result['value']:
                        if row['PROJECT_MEMBER'] == new_lead_urn:
                            # check if member has lead privileges
                            q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value).\
                                filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == row['PROJECT_MEMBER_UID']). \
                                filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
                            rows = q.all()
                            if len(rows) == 0 or rows[0][0] != 'true':
                                session.close()
                                raise CHAPIv1ArgumentError('New project lead not authorized')
                            new_project_lead = row['PROJECT_MEMBER_UID']
                            break

#                    q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value).\
#                    filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == new_project_lead).\
#                    filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
#                    rows = q.all()
#                    if len(rows) == 0 or rows[0][0] != 'true':
#                        raise CHAPIv1ArgumentError('New project lead not authorized')


        result = self.modify_membership(session, ProjectMember, client_uuid, \
                                          project_id, project_urn, \
                                          options, 'project_id', \
                                          'PROJECT_MEMBER', 'PROJECT_ROLE', \
                                          'project')

        # identify all slices in project and new project lead
        q = session.query(self.db.SLICE_TABLE)
        q = q.filter(self.db.SLICE_TABLE.c.project_id == project_id)
        rows = q.all()
    
        slices = [row.slice_id for row in rows]
        slice_urns = {}
        for row in rows:
            slice_urns[row.slice_id] = row.slice_urn
        project_lead = self.get_project_lead(session, project_id)
        project_lead_urn = self.get_member_urn_for_id(session, project_lead)

        # if project lead has changed, change in pa_project table
        if new_project_lead != old_project_lead:
            q = session.query(Project)
            q = q.filter(Project.project_id == project_id)
            q = q.update({"lead_id" : new_project_lead})
            chapi_audit_and_log(SA_LOG_PREFIX, "Changed lead for project %s from %s to %s" % (name, old_lead_urn, project_lead_urn), logging.INFO, {'user': user_email})
            # FIXME: Add call to log service? It would be a duplicate of sorts

 
        # make new project lead admin on slices
            opt = [{'SLICE_MEMBER': project_lead_urn, 'SLICE_ROLE': 'ADMIN'}]
            result3 = self.lookup_slices_for_member(client_cert, \
                                 project_lead_urn, credentials, {})

            # change lead's role on slices he/she is member of
            for slice in result3['value']:
                # skip slice if not in current project
                if slice['SLICE_UID'] not in slices:
                    continue
                del(slice_urns[slice['SLICE_UID']])
                if slice['SLICE_ROLE'] not in ['LEAD', 'ADMIN']:
                    options = {'members_to_change': opt}
                    self.modify_membership(session, SliceMember, client_uuid, \
                           slice['SLICE_UID'], slice['SLICE_URN'], options, \
                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')
                    
            # add lead to slices not yet a member of
            for slice_id, slice_urn in slice_urns.iteritems():
                 options = {'members_to_add': opt}
                 self.modify_membership(session, SliceMember, client_uuid, \
                           slice_id, slice_urn, options, \
                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

        # now delete all removed members from slices
        if 'members_to_remove' in options:
            for member in options['members_to_remove']:
                result3 = self.lookup_slices_for_member(client_cert, member, \
                                                        credentials, {})
                for slice in result3['value']:
                    # skip slices that are not part of the current project
                    if not slice['SLICE_UID'] in slices:
                        continue
                    options = {'members_to_remove': [member]}

                    # if member is lead on the slice, make a new lead
                    if slice['SLICE_ROLE'] == 'LEAD':
                        opt = [{'SLICE_MEMBER': project_lead_urn,
                                'SLICE_ROLE': 'LEAD'}]
                        q = session.query(SliceMember.member_id)
                        q = q.filter(SliceMember.slice_id == slice['SLICE_UID'])
                        q = q.filter(SliceMember.member_id == project_lead)
                        if len(q.all()) > 0:
                            options['members_to_change'] = opt
                        else:
                            options['members_to_add'] = opt
                    

                    self.modify_membership(session, SliceMember, client_uuid, \
                             slice['SLICE_UID'], slice['SLICE_URN'], options, \
                             'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

        session.commit()
        session.close()

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # change the membership in a project
    def modify_slice_membership(self, client_cert, slice_urn, \
                                credentials, options):

        method = 'modify_slice_membership'
        args = {'slice_urn' : slice_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid)

        session = self.db.getSession()
        slice_id = self.get_slice_id(session, "slice_urn", slice_urn) # MIK: only non-expired slice
        old_slice_lead = self.get_slice_lead(session, slice_id)

        result = self.modify_membership(session, SliceMember, client_uuid, \
                                          slice_id, slice_urn, \
                                          options, 'slice_id', \
                                          'SLICE_MEMBER', 'SLICE_ROLE', \
                                          'slice')
        

        # FIXME: Validate that new slice lead is not a project auditor

        new_slice_lead = self.get_slice_lead(session,slice_id)

        # if slice lead has changed, change in sa_slice table
        if new_slice_lead != old_slice_lead:
            q = session.query(Slice)
            q = q.filter(Slice.slice_id == slice_id)
            q = q.update({"owner_id" : new_slice_lead})
            
        session.commit()
        session.close()

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

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
                if not member_obj.member_id:
                    session.close()
                    raise CHAPIv1ArgumentError('No such member ' + \
                        member[member_str])
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
                # FIXME: Email admins of new project members

        # Log all changes
        if 'members_to_change' in options:
            members_to_change = options['members_to_change']
            for member_to_change in members_to_change:
                member_urn = member_to_change[member_str]
                member_name = get_name_from_urn(member_urn)
                member_role = member_to_change[role_str]
                self.logging_service.log_event(
                    "Changed member %s to role %s in %s %s" % \
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

    def get_member_urn_for_id(self, session, id):
        q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == "urn")
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == id)
        rows = q.all()
        if len(rows) > 0:
           return rows[0].value
        return None

    def get_project_lead(self, session, project_id):
        q = session.query(ProjectMember.member_id)
        q = q.filter(ProjectMember.project_id == project_id)
        lead_role = str(self.get_role_id(session, "LEAD"))
        q = q.filter(ProjectMember.role == lead_role)
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

    # Lookup attributes for project
    def lookup_project_attributes(self, client_cert, project_urn, \
                                      credentials, options):
        method = 'lookup_project_attributes'
        args = {'project_urn' : project_urn}

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid)

        session = self.db.getSession()
        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        q = session.query(self.db.PROJECT_ATTRIBUTE_TABLE )
        q = q.filter(self.db.PROJECT_ATTRIBUTE_TABLE.c.project_id==project_id)
        rows = q.all()
        session.close()
        attribs = []
        for row in rows:
            attrib_name = row.name
            attrib_value = row.value
            attrib = {'name' : attrib_name, 'value' : attrib_value}
            attribs.append(attrib)
        result = self._successReturn(attribs)
        return result

    def get_slice_lead(self, session, slice_id):
        q = session.query(SliceMember.member_id)
        q = q.filter(SliceMember.slice_id == slice_id)
        lead_role = str(self.get_role_id(session, "LEAD"))
        q = q.filter(SliceMember.role == lead_role)
        rows = q.all()
        if len(rows) > 0:
           return rows[0].member_id
        return None

    # Sliver Info API

    def create_sliver_info(self, client_cert, credentials, options):
        session = self.db.getSession()
        sliver = SliverInfo()
        for field, value in options['fields'].iteritems():
           setattr(sliver, SA.sliver_info_field_mapping[field], value)
        if not sliver.creation:
            sliver.creation = datetime.utcnow()
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
        return self._successReturn(True)

    def update_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options):
        session = self.db.getSession()
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver_urn)
        vals = {}
        for field, value in options['fields'].iteritems():
           vals[SA.sliver_info_field_mapping[field]] = value
        q.update1(vals)
        session.commit()
        session.close()
        return self._successReturn(True)

    def lookup_sliver_info(self, client_cert, credentials, options):
        columns, match_criteria = \
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

        method = 'create_request'
        args = {'context_type' : context_type, 'context_id' : context_id,
                'request_type' : request_type, 'request_text' : request_text,
                'request_details' : request_details}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        session = self.db.getSession()
        ins = self.db.PROJECT_REQUEST_TABLE.insert().values(
            context_type = context_type, \
                context_id = context_id, \
                request_type = request_type, \
                request_text = request_text, \
                request_details = request_details, \
                creation_timestamp = datetime.utcnow(), \
                status = PENDING_STATUS, \
                requestor = client_uuid)
        result = session.execute(ins)
        
        query = "select max(id) from pa_project_member_request"
        request_id  = session.execute(query).fetchone().values()[0]
        session.commit()
        session.close()
        result = self._successReturn(request_id)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    def resolve_pending_request(self, client_cert, context_type, request_id, \
                                    resolution_status, resolution_description,  \
                                    credentials, options):

        method = 'resolve_pending_request'
        args = {'context_type' : context_type, 'request_id' : request_id,
                'resolution_status' : resolution_status, 'resolution_description' : resolution_description}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        client_uuid = get_uuid_from_cert(client_cert)
        session = self.db.getSession()

        update_values = {'status' : resolution_status, 
                         'resolver' : client_uuid, 
                         'resolution_description' : resolution_description,
                         'resolution_timestamp' : datetime.utcnow() 
                         }
        update = self.db.PROJECT_REQUEST_TABLE.update(values=update_values)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        session.execute(update)
        session.commit()
        session.close()
        result = self._successReturn(True)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def get_requests_for_context(self, client_cert, context_type, \
                                 context_id, status, \
                                 credentials, options):
        method = 'get_requests_for_context'
        args = {'context_type' : context_type, 'context_id' : context_id,
                'status' : status}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

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
        result = self._successReturn(result)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def get_requests_by_user(self, client_cert, member_id, context_type, \
                                 context_id, status, \
                                 credentials, options):
        method = 'get_requests_by_user'
        args = {'member_id' : member_id, 'context_type' : context_type,
                'context_id' : context_id, 'status' : status}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

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
        method = 'get_pending_requests_for_user'
        args = {'member_id' : member_id, 'context_type' : context_type, 
                'context_id' : context_id}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        session = self.db.getSession()
        # Filter those projects with pending requsts to those for which
        # Given member is lead or admin
        q = session.query(self.db.PROJECT_REQUEST_TABLE)
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
        result = self._successReturn(result)

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    def get_number_of_pending_requests_for_user(self, client_cert, member_id, \
                                                    context_type, context_id, \
                                                    credentials, options):
        method = 'get_number_of_pending_requests_for_user'
        args = {'member_id' : member_id, 'context_type' : context_type, 
                'context_id' : context_id}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        requests = self.get_pending_requests_for_user(client_cert, member_id, \
                                                          context_type, context_id,  \
                                                          credentials, options)
        if requests['code'] != NO_ERROR:
            return requests
        result = self._successReturn(len(requests['value']))

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result


    def get_request_by_id(self, client_cert, request_id, context_type, \
                              credentials, options):
        method = 'get_request_by_id'
        args = {'request_id' : request_id, 'context_type' : context_type}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        session = self.db.getSession()
        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        rows = q.all()
        session.close()
        if len(rows) == 0:
            return self._successReturn(None)
        result = \
            self._successReturn(construct_result_row(rows[0], 
                                                     SA.project_request_columns, 
                                                     SA.project_request_field_mapping))

        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})
        return result

    # Add an attribute to a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name, 'attr_value' : attr_value}
    def add_project_attribute(self, \
                                  client_cert, project_urn, \
                                  credentials, options):
        method = 'add_project_attribute'
        args = {'project_urn' : project_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        if not options or 'attr_name' not in options or 'attr_value' not in options:
            raise CHAPIv1ArgumentError("Missing attribute name/value for add_project_attribute")

        attr_name = options['attr_name']
        attr_value = options['attr_value']

        session = self.db.getSession()

        project_name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, 'project_name', project_name)

        ins = self.db.PROJECT_ATTRIBUTE_TABLE.insert().values(project_id = project_id, 
                                                              name = attr_name, 
                                                              value = attr_value)

        session.execute(ins)
        result = True

        session.commit()
        session.close()
        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})

        return self._successReturn(result)

    # remove an attribute from a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name}
    def remove_project_attribute(self, \
                                     client_cert, project_urn, \
                                     credentials, options):
        method = 'remove_project_attribute'
        args = {'project_urn' : project_urn}
        user_email = get_email_from_cert(client_cert)
        chapi_log_invocation(SA_LOG_PREFIX, method, credentials, options, args, {'user': user_email})

        if not options or 'attr_name' not in options:
            raise CHAPIv1ArgumentError("Missing attribute name/value for remove_project_attribute")
        attr_name = options['attr_name']

        session = self.db.getSession()

        project_name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, 'project_name', project_name)

        q = session.query(self.db.PROJECT_ATTRIBUTE_TABLE)
        q = q.filter(self.db.PROJECT_ATTRIBUTE_TABLE.c.project_id == project_id)
        q = q.filter(self.db.PROJECT_ATTRIBUTE_TABLE.c.name == attr_name)

        q.delete(synchronize_session='fetch')
        result = True

        session.commit()
        session.close()
        chapi_log_result(SA_LOG_PREFIX, method, result, {'user': user_email})

        return self._successReturn(result)

