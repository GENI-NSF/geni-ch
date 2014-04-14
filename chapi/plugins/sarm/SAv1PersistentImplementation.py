#----------------------------------------------------------------------
# Copyright (c) 2011-2014 Raytheon BBN Technologies
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

import datetime as dt
from dateutil.relativedelta import relativedelta
import dateutil.parser
import dateutil.tz
import logging
import os
import re
import uuid
from sqlalchemy import *
from sqlalchemy.orm import mapper

import amsoil.core.pluginmanager as pm

import gcf.sfa.trust.gid as gid
from gcf.sfa.trust.certificate import Certificate
import gcf.geni.util.cred_util as cred_util
import gcf.geni.util.cert_util as cert_util
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
from tools.chapi_utils import *

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

class ProjectInvitation(object):
    pass

class ProjectAttribute(object):
    pass

# Implementation of SA that speaks to GPO Slice and projects table schema
class SAv1PersistentImplementation(SAv1DelegateBase):

    def __init__(self):
        super(SAv1PersistentImplementation, self).__init__()
        self.db = pm.getService('chdbengine')
        self.config = pm.getService('config')
        self.cert = self.config.get('chapi.sa_cert')
        self.key = self.config.get('chapi.sa_key')
        self.urn = get_urn_from_cert(open(self.cert).read())

        self.logging_service = pm.getService('loggingv1handler')
        self._ma_handler = pm.getService('mav1handler')

        self.portal_admin_email = self.config.get('chapi.portal_admin_email')
        self.portal_help_email = self.config.get('chapi.portal_help_email')
        self.ch_from_email = self.config.get('chapi.ch_from_email')

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
        mapper(ProjectInvitation, self.db.PROJECT_INVITATION_TABLE, \
                   primary_key = self.db.PROJECT_INVITATION_TABLE.c.id)
        mapper(ProjectAttribute, self.db.PROJECT_ATTRIBUTE_TABLE, \
                   primary_key = self.db.PROJECT_ATTRIBUTE_TABLE.c.id)

    def get_version(self, session):
        import flask
        api_versions = \
            {chapi.Parameters.VERSION_NUMBER : flask.request.url_root}
        implementation_info = get_implementation_info(SA_LOG_PREFIX)
        version_info = {"VERSION" : chapi.Parameters.VERSION_NUMBER, 
                        "URN " : self.urn,
                        "IMPLEMENTATION" : implementation_info,
                        "SERVICES" : SA.services,
                        "CREDENTIAL_TYPES" : SA.credential_types, 
                        "ROLES" : attribute_type_names.values(),
                        "API_VERSIONS" : api_versions,
                        "FIELDS": SA.supplemental_fields}
        result = self._successReturn(version_info)

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
            q = q.filter(or_(table.expiration > text("now() at time zone 'utc'"),table.expiration == None))
        else:
            q = q.filter(table.expiration < text("now() at time zone 'utc'"))

        return q

    def update_expirations(self, client_uuid, type, resurrect, session):
        if resurrect:
            old_flag = True
            new_flag = False
            label = "Restored previously expired"
        else:
            old_flag = False
            new_flag = True
            label = "Expired"

        q = self.get_expiration_query(session, type, old_flag, resurrect)
        rows = q.all()

        if len(rows) > 0:
            update_fields = {'expired' : new_flag}
            # Force execute query in DB for time comparisons to happen there
            # And so if in this session we just updated a project expiration, it is seen
            q = q.update(update_fields, 'fetch')

        for row in rows:
            if type == 'slice':
                name = row.slice_name
                attrs = {"SLICE" : row.slice_id, "PROJECT" : row.project_id}
            else:
                name = row.project_name
                attrs = {"PROJECT" : row.project_id}
            # Do not log as this user, log as the None UID
            logresult = None
            try:
                lmessage = "%s %s %s" % (label, type, name)
                args = {'message' : lmessage, 'attributes' : attrs}
                chapi_log_invocation(LOG_LOG_PREFIX, "log_event", [], {}, args)
                logresult = self.logging_service._delegate.log_event(None, lmessage, attrs, [], {}, session, none_user_id=True)
            except Exception, e:
                if not isinstance(e, CHAPIv1BaseError):
                    e = CHAPIv1ServerError(str(e))
                logresult = { 'code' : e.code , 'output' : str(e), 'value' : None }
                chapi_warn(SA_LOG_PREFIX, "Failed to log_event in update_expirations: %s" % e)
            finally:
                chapi_log_result(LOG_LOG_PREFIX, 'log_event', logresult)

    # Check for
    #   Recently expired slices and set their expired flags to 't'
    def update_slice_expirations(self, client_uuid, session):
        self.update_expirations(client_uuid, 'slice', False, session)

    # Check for 
    #   Recently expired projects and set their expired flags to 't'
    #   Recently extended expired projects and set their expired flags to 'f'
    def update_project_expirations(self, client_uuid, session):
        self.update_expirations(client_uuid, 'project', False, session)
        self.update_expirations(client_uuid, 'project', True, session)
        self.update_expirations(client_uuid, 'slice', False, session)

    def lookup_slices(self, client_cert, credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        selected_columns, match_criteria = \
            unpack_query_options(options, SA.slice_field_mapping)

        # If query asked for only a single empty list of identifiers
        # Skip the query
        if match_criteria and len(match_criteria) == 1:
            match_values = match_criteria.values()[0]
            if len(match_values) == 0:
                slices = {}
                result = self._successReturn(slices)
                chapi_info(SA_LOG_PREFIX,
                           "Returning empty list of slices for empty criteria")
                return result

        q = session.query(self.db.SLICE_TABLE, self.db.PROJECT_TABLE.c.project_id, self.db.PROJECT_TABLE.c.project_name)

        q = q.filter(self.db.SLICE_TABLE.c.project_id == self.db.PROJECT_TABLE.c.project_id)

        q = add_filters(q, match_criteria, self.db.SLICE_TABLE, SA.slice_field_mapping, session)

        rows = q.all()

        # in python 2.7, could do dictionary comprehension !!!!!!!!
        slices = {}
        for row in rows:
            slices[row.slice_urn] = construct_result_row(row, \
                selected_columns, SA.slice_field_mapping, session)

        result = self._successReturn(slices)

        return result

    # members in a slice
    def lookup_slice_members(self, client_cert, slice_urn, 
                             credentials, options, session):
        slice_id = None
        if "match" in options:
            if 'SLICE_UID' in options['match']:
                slice_id = options['match']['SLICE_UID']

        if slice_id == None:
            q = session.query(self.db.SLICE_TABLE.c['slice_id'])
            q = q.filter(self.db.SLICE_TABLE.c['slice_urn']==slice_urn)
            q = q.order_by(desc(self.db.SLICE_TABLE.c['creation']))
            # FIXME: Only non expired?
#            q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
            rows = q.all()
            if len(rows) > 0:
                slice_id = rows[0][0]
            else:
                raise CHAPIv1ArgumentError("Unknown slice %s - cannot lookup members" % slice_urn)

        result = self.lookup_members(client_cert, self.db.SLICE_TABLE, 
                                     self.db.SLICE_MEMBER_TABLE, slice_urn, "slice_urn", 
                                     "slice_id", "SLICE_ROLE", "SLICE_MEMBER", "SLICE_MEMBER_UID",
                                     slice_id, session)

        return result


    # members in a project
    def lookup_project_members(self, client_cert, project_urn, \
                               credentials, options, session):

        project_name = from_project_urn(project_urn)
        result = self.lookup_members(client_cert, self.db.PROJECT_TABLE, 
                                     self.db.PROJECT_MEMBER_TABLE, project_name, "project_name", 
                                     "project_id", "PROJECT_ROLE", "PROJECT_MEMBER", 
                                     "PROJECT_MEMBER_UID", None, session)

        return result


    # shared code for lookup_slice_members() and lookup_project_members()
    def lookup_members(self, client_cert, table, member_table, \
                           name, name_field, \
                           id_field, role_txt, member_txt, member_uid_txt, 
                       id_value, session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

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
        members = [{role_txt: row.name, member_txt: row.value, \
                        member_uid_txt : row.member_id} for row in rows]
        return self._successReturn(members)

    def lookup_slices_for_member(self, client_cert, member_urn, \
                                 credentials, options, session):
        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        rows = self.lookup_for_member(member_urn, self.db.SLICE_TABLE, \
                  self.db.SLICE_MEMBER_TABLE, "slice_urn", "slice_id", session)
        slices = [{"SLICE_ROLE" : row.name, \
                       "SLICE_UID" : row.slice_id, \
                       "SLICE_URN": row.slice_urn, \
                      "EXPIRED": row.expired } \
                  for row in rows]

        result = self._successReturn(slices)

        return result

    def get_credentials(self, client_cert, slice_urn, credentials, options, 
                        session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        q = session.query(self.db.SLICE_TABLE.c.expiration, \
                              self.db.SLICE_TABLE.c.certificate)
        q = q.filter(self.db.SLICE_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self.db.SLICE_TABLE.c.expired == 'f')
        rows = q.all()
        if len(rows) == 0:
            raise CHAPIv1ArgumentError("Can't get slice credential " + \
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
            [{'geni_type' : 'geni_sfa', 'geni_version' : 3, 'geni_value' : cred} 
             for cred in sfa_raw_creds]
        abac_creds = \
            [{'geni_type' : 'geni_abac', 'geni_version' : 1, 'geni_value' : cred} 
             for cred in abac_raw_creds]
        creds = sfa_creds + abac_creds

        result = self._successReturn(creds)

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
        # *** MSB 2-24-2014
        # *** We are adding this for now to disallow creating 
        # *** slices that differ only by case. If case insensitivity
        # *** is the decided semantics, we need to make changes in lookup
        # *** and other methods as well
        if field == 'slice_name':
            q = q.filter(func.upper(getattr(Slice, field)) == value.upper())
        else:
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
        # *** MSB 2-24-2014
        # *** We are adding this for now to disallow creating 
        # *** projects that differ only by case. If case insensitivity
        # *** is the decided semantics, we need to make changes in lookup
        # *** and other methods as well
        q = q.filter(func.upper(getattr(Project, field)) == value.upper())
        rows = q.all()
        if (len(rows) == 0):
            return None
        return rows[0].project_id

    # shared by create_slice() and create_project()
    def finish_create(self, session, object, field_mapping, extra = {}):
        chapi_debug(SA_LOG_PREFIX, "finish_create: %s %s %s" % (object, field_mapping, extra))
        ret = extra.copy()
        for k, v in field_mapping.iteritems():
            if isinstance(v, types.DictionaryType):
                base_field = v['base_field']
                to_external = v['to_external']
                internal_value = getattr(object, base_field)
                external_value = to_external(internal_value, session)
                ret[k] = external_value
            elif isinstance(v, types.StringType):
                ret[k] = getattr(object, v)
        session.add(object)
        return self._successReturn(ret)

    # create a new slice
    def create_slice(self, client_cert, credentials, options, session):
        client_uuid = get_uuid_from_cert(client_cert)
        user_email = get_email_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        name = options["fields"]["SLICE_NAME"]

        # Create email if not provided
        # Do not set a fake email for now, since that breaks FOAM
        # FIXME: Support a real slice email address
#        if not '_GENI_SLICE_EMAIL' in options['fields'] or \
#           not options['fields']['_GENI_SLICE_EMAIL']:
#            options['fields']['_GENI_SLICE_EMAIL'] = \
#                'slice-%s@example.com' % name

        options['fields']['_GENI_SLICE_EMAIL'] = None

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
                    raise CHAPIv1ArgumentError('No project with urn ' + value)
            else:
                setattr(slice, SA.slice_field_mapping[key], value)

        # Check if project is not null
        if project_urn == None:
            raise CHAPIv1ArgumentError("No project specified for create_slice");

        # Check if project is not expired, get expiration for later use
        q = session.query(Project.expired, Project.expiration)
        q = q.filter(Project.project_id == slice.project_id)
        project_info = q.one()
        expired = project_info.expired
        project_expiration = project_info.expiration
        if project_info.expired:
            raise CHAPIv1ArgumentError("May not create a slice on expired project %s" % project_urn);
        
        # Check that slice name is valid
        if ' ' in name:
            raise CHAPIv1ArgumentError('Slice name may not contain spaces.')
        elif len(name) > 19: # FIXME: Externalize this
            raise CHAPIv1ArgumentError('Slice name %s is too long - use at most 19 characters.' %name)
            
        # FIXME: Externalize this
        pattern = '^[a-zA-Z0-9][a-zA-Z0-9-]{0,18}$'
        valid = re.match(pattern,name)
        if valid == None:
            raise CHAPIv1ArgumentError('Slice name %s is invalid - use at most 19 alphanumeric characters or hyphen. No leading hyphen.' %name)
        # before fill in rest, check that slice does not already exist
        same_name = self.get_slice_ids(session, "slice_name", name)
        if same_name:
            same_project = self.get_slice_ids(session, "project_id",
                                              slice.project_id)
            if same_project and (set(same_name) & set(same_project)):
                raise CHAPIv1DuplicateError('There already exists a slice named ' +
                                            name + ' in project ' + project_name)

        slice.creation = dt.datetime.utcnow()
        # FIXME: Why check if slice.expiration is set. We are creating the slice here - how can it be set?
        if not slice.expiration:
            # FIXME: Externalize the #7 here
            slice.expiration = slice.creation + relativedelta(days=SA.SLICE_DEFAULT_LIFE_DAYS)
        else:
            # Make timzeone UTC naive
            slice.expiration = dateutil.parser.parse(slice.expiration)
            slice.expiration = slice.expiration.astimezone(dateutil.tz.tzutc())
            slice.expiration = slice.expiration.replace(tzinfo=None)

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
        members = self.lookup_project_members(client_cert,project_urn, credentials,{}, session)
        if members['code'] != NO_ERROR:
            raise CHAPIv1ArgumentError('No members found for project ' + project_urn)
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

        # do the database write
        result = self.finish_create(session, slice, SA.slice_field_mapping)

        # Log the slice create event
        attribs = {"SLICE" : slice.slice_id, "PROJECT" : slice.project_id}
        self.logging_service.log_event("Created slice " + name, 
                                       attribs, credentials, options,
                                       session=session)
        chapi_audit_and_log(SA_LOG_PREFIX, "Created slice " + name + " in project " + slice.project_id, logging.INFO, {'user': user_email})

        return result

    # update an existing slice
    def update_slice(self, client_cert, slice_urn, credentials, options,
                     session):

        client_uuid = get_uuid_from_cert(client_cert)
        user_email = get_email_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        slice_uuid = \
            self.get_slice_id(session, 'slice_urn', slice_urn) # MIK: only non-expired slices
        if not slice_uuid: 
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
            raise CHAPIv1ArgumentError('Cannot update slice %s: project is expired' % slice_urn)

        q = session.query(Slice.expired, Slice.expiration, Slice.certificate, Slice.slice_email, Slice.slice_id, Slice.creation)
        q = q.filter(Slice.slice_id == slice_uuid)
        slice_info = q.one()
        if slice_info.expired:
            raise CHAPIv1ArgumentError('Cannot update or renew an expired slice (%s expired at %s)' % (slice_urn, slice_info.expiration.isoformat()))
        slice_expiration = slice_info.expiration
        max_exp = dt.datetime.utcnow() + relativedelta(days=SA.SLICE_MAX_RENEWAL_DAYS)
#        # If this is marked as a long lived slice, then
#        if True or slice_info.long_lived:
#            max_exp = dt.datetime.max
        new_exp = None # A dateutil for the new slice expiration

        for field, value in options['fields'].iteritems():
            if field=="SLICE_EXPIRATION":
                # convert value to datetime object
                new_exp = dateutil.parser.parse(value)
                # Be sure the requested time is naive UTC
                if new_exp.tzinfo:
                    tz_utc = dateutil.tz.tzutc()
                    new_exp = new_exp.astimezone(tz_utc)
                    new_exp = new_exp.replace(tzinfo=None)
                    value = new_exp
#                chapi_debug(SA_LOG_PREFIX, "Slice %s Requested new slice expiration %s" % (slice_name, value))
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
                    if slice_expiration > max_exp:
                        raise CHAPIv1ArgumentError('Cannot renew slice - it is already at or past the usual max of %d days past now (%s expires at %s)' % (SA.SLICE_MAX_RENEWAL_DAYS, slice_urn, slice_expiration.isoformat()))
#                    chapi_debug(SA_LOG_PREFIX, "Slice %s Reset renew request %s to max exp %s" % (slice_name, new_exp, max_exp))
                # don't shorten slice lifetime
                if slice_expiration > new_exp:
                    raise CHAPIv1ArgumentError('Cannot shorten slice lifetime (%s expires at %s)' % (slice_urn, slice_expiration.isoformat()))

                # regenerate cert if necessary
                cert = Certificate(string = slice_info.certificate)
                cert_exp = dateutil.parser.parse(cert.cert.get_notAfter())
                cert_exp = cert_exp.replace(tzinfo = new_exp.tzinfo)
                if (cert_exp < new_exp):
                    cert, k = cert_util.create_cert(slice_urn, \
                                                        issuer_key = self.key, issuer_cert = self.cert, \
                                                        lifeDays = (new_exp - slice_info.creation).days + SA.SLICE_CERT_LIFETIME, \
                                                        email = slice_info.slice_email, uuidarg=slice_info.slice_id)
                    # FIXME: Ticket #149: Save the slice key and
                    # re-use it when re-generating the slice certifate
                    # updates['key'] = k.save_to_string()
                    updates['certificate'] = cert.save_to_string()
                    chapi_warn(SA_LOG_PREFIX, 
                               "Re-generated certificate for slice %s to last past new expiration %s" % (slice_urn,
                                                                                                         new_exp.isoformat()), 
                               {'user': user_email})
                    
            updates[SA.slice_field_mapping[field]] = value

        q = q.update(updates)

        # Log the update slice
        client_uuid = get_uuid_from_cert(client_cert)
        attribs = {"PROJECT" : project_uuid, "SLICE" : slice_uuid}
        if "SLICE_EXPIRATION" in options['fields']: 
            # FIXME: Format in RFC3339 format not iso
            self.logging_service.log_event("Renewed slice %s until %s" % \
                                               (slice_name, new_exp.isoformat()), \
                                               attribs, credentials, options,
                                           session=session)
        else:
            self.logging_service.log_event("Updated slice " + slice_name, 
                                           attribs, credentials, options,
                                           session=session)

        result = self._successReturn(True)

        return result

    # create a new project
    def create_project(self, client_cert, credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)
        user_email = get_email_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        name = options["fields"]["PROJECT_NAME"]
        # check that project name is valid
        if ' ' in name:
            raise CHAPIv1ArgumentError('Project name may not contain spaces.')
        elif len(name) > 32: # FIXME: Externalize this
            raise CHAPIv1ArgumentError('Project name %s is too long - use at most 32 characters.' %name)
            
        # FIXME: Put this in a constants file
        pattern = '^[a-zA-Z0-9][a-zA-Z0-9-_]{0,31}$'
        valid = re.match(pattern,name)
        if valid == None:
            raise CHAPIv1ArgumentError('Project name %s is invalid - use at most 32 alphanumeric characters or hyphen or underscore. No leading hyphen or underscore.' %name)
        
        # check that project does not already exist
        if self.get_project_id(session, "project_name", name):
            raise CHAPIv1DuplicateError('There already exists a project named ' + name)

        # fill in the fields of the object
        project = Project()
        for key, value in options["fields"].iteritems():
            setattr(project, SA.project_field_mapping[key], value)
        project.creation = dt.datetime.utcnow()
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

        attribs = {"PROJECT" : project.project_id, "MEMBER" : project.lead_id}

        # do the database write
        result = self.finish_create(session, project,  SA.project_field_mapping, \
                                        {"PROJECT_URN": row_to_project_urn(project)})

        # get name of project lead
        ma_options = {'match' : {'MEMBER_UID' : project.lead_id },'filter': ['_GENI_MEMBER_DISPLAYNAME','MEMBER_FIRSTNAME','MEMBER_LASTNAME','MEMBER_EMAIL']}  
        member_info = self._ma_handler._delegate.lookup_identifying_member_info(client_cert,credentials,ma_options, session)
        leadname = ""
        info = member_info['value']
        if len(info) > 0:
            for row in info:
                leadname = get_member_display_name(info[row],row)

        self.logging_service.log_event("Created project " + name + " with lead " + leadname, 
                                       attribs, credentials, options,
                                       session=session)
        chapi_audit_and_log(SA_LOG_PREFIX, "Created project " + name + " with lead " + leadname, logging.INFO, {'user': user_email})

        # Email the admins that the project was created
        subject = "New GENI CH project created"
        msgbody = "Created project: %s with lead %s on CH %s" %(name, leadname, self.config.get("chrm.authority"))
        tolist = [self.portal_admin_email]
        send_email(tolist, self.ch_from_email, self.portal_help_email,subject,msgbody)

        return result

    # update an existing project
    def update_project(self, client_cert, project_urn, credentials, options,
                       session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        name = from_project_urn(project_urn)
        project_uuid = self.get_project_id(session, 'project_name', name)
        if not project_uuid:
            raise CHAPIv1ArgumentError('No project found with urn ' + project_urn)
        q = session.query(Project)
        q = q.filter(getattr(Project, "project_name") == name)
        updates = {}
        # Handle empty string for no expiration
        if (options['fields'].has_key('PROJECT_EXPIRATION')
            and not options['fields']['PROJECT_EXPIRATION']):
            options['fields']['PROJECT_EXPIRATION'] = None

        # FIXME: Are there any rules on TZ for project expiration?

        # Say what was updated in log message
        change = ""
        row = q.one()
        if options['fields'].has_key('PROJECT_EXPIRATION'):
            newval = options['fields']['PROJECT_EXPIRATION']
            if (newval is None and row.expiration is not None) or \
                    (newval is not None and row.expiration is None):
                change = " expiration"
            elif newval is not None and row.expiration is not None:
                newtime = dateutil.parser.parse(newval)
                if newtime.tzinfo:
                    tz_utc = dateutil.tz.tzutc()
                    newtime = newtime.astimezone(tz_utc)
                    newtime = newtime.replace(tzinfo=None)
                curtime = row.expiration
                if newtime - curtime > dt.timedelta.resolution:
                    change = " expiration"
        if options['fields'].has_key('PROJECT_DESCRIPTION') and \
                options['fields']['PROJECT_DESCRIPTION'] != row.project_purpose:
            if change != "":
                change = change + ", " + "description"
            else:
                change = " description"

        for field, value in options['fields'].iteritems():
            updates[SA.project_field_mapping[field]] = value
        q = q.update(updates)

        # Log the update project
        client_uuid = get_uuid_from_cert(client_cert)
        attribs = {"PROJECT" : project_uuid}

        self.logging_service.log_event("Updated project " + name + change, 
                                       attribs, credentials, options,
                                       session=session)

        # Force this project to be expired/unexpired and logged now
        if options['fields'].has_key('PROJECT_EXPIRATION'):
            self.update_project_expirations(client_uuid, session)

        result = self._successReturn(True)

        return result

    # get info on a set of projects
    def lookup_projects(self, client_cert, credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        columns, match_criteria = \
            unpack_query_options(options, SA.project_field_mapping)

        if match_criteria.has_key('PROJECT_URN'):
            urns = match_criteria['PROJECT_URN']
            del match_criteria['PROJECT_URN']
            if not isinstance(urns, list):
                urns = [urns]
            match_criteria['PROJECT_NAME'] = \
                [from_project_urn(urn) for urn in urns]

        q = session.query(self.db.PROJECT_TABLE)
        q = add_filters(q, match_criteria, self.db.PROJECT_TABLE, \
                        SA.project_field_mapping, session)
        rows = q.all()
        projects = {}
        for row in rows:
            projects[row_to_project_urn(row)] = \
                construct_result_row(row, columns, \
                                         SA.project_field_mapping, session)
        result = self._successReturn(projects)

        return result

    # get the projects associated with a member
    def lookup_projects_for_member(self, client_cert, member_urn, \
                                   credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        rows = self.lookup_for_member(member_urn, self.db.PROJECT_TABLE, \
                                          self.db.PROJECT_MEMBER_TABLE, 
                                      "project_name", "project_id", 
                                      session)
        projects = [{"PROJECT_ROLE" : row.name, \
                         "PROJECT_UID" : row.project_id, \
                         "PROJECT_URN": row_to_project_urn(row), \
                         "EXPIRED" : row.expired } \
                        for row in rows]
        result = self._successReturn(projects)

        return result

    # shared code between projects and slices
    def lookup_for_member(self, member_urn, table, member_table, \
                          name_field, id_field, session):
        q = session.query(member_table, self.db.MEMBER_ATTRIBUTE_TABLE,
                          table.c[name_field], self.db.ROLE_TABLE.c.name, table.c['expired'])
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.value == member_urn)
        q = q.filter(member_table.c.member_id == \
                     self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(table.c[id_field] == member_table.c[id_field])
        q = q.filter(member_table.c.role == self.db.ROLE_TABLE.c.id)
        rows = q.all()
        return rows

    # change the membership in a project
    def modify_project_membership(self, client_cert, project_urn, \
                                  credentials, options, session):
        client_uuid = get_uuid_from_cert(client_cert)
        user_email = get_email_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        old_project_lead = self.get_project_lead(session, project_id)
        new_project_lead = old_project_lead;
        old_lead_urn = self.get_member_urn_for_id(session, old_project_lead)

        # Prepare a 'speaking_for' dict for updating options for
        # individual calls below
        speaking_for = dict()
        if 'speaking_for' in options:
            speaking_for['speaking_for'] = options['speaking_for']

        # If we are removing the lead, make sure there is an authorized admin on the project
        #   If yes, make the admin be the lead, and the current lead be a member
        #   If no, FAIL

        if 'members_to_remove' in options:
            for member in options['members_to_remove']:
                if (member==old_lead_urn):
                    lookup_result = self.lookup_project_members(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        {}, session)
                    if lookup_result['code'] != NO_ERROR:
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
                            
                            role_options = {'members_to_change': [{'PROJECT_MEMBER': old_lead_urn, 'PROJECT_ROLE': 'MEMBER'},{'PROJECT_MEMBER': new_lead_urn, 'PROJECT_ROLE': 'LEAD'}]}
                            role_options.update(speaking_for)
                            result = self.modify_membership(client_cert, session, ProjectMember, client_uuid, \
                                                                project_id, project_urn, \
                                                                credentials, role_options, 'project_id', \
                                                                'PROJECT_MEMBER', 'PROJECT_ROLE', \
                                                                'project')

                            break
                    if new_lead_urn==None:
                        raise CHAPIv1ArgumentError('Cannot remove %s lead %s: ' + 
                                                   'No project admins are authorized to be a project lead' % 
                                                   (project_urn, old_lead_urn))
                    
        if 'members_to_change' in options:
            # if project lead will change, make sure new project lead authorized
            for change in options['members_to_change']:
                if change['PROJECT_ROLE'] == 'LEAD':
                    lookup_result = self.lookup_project_members(client_cert, \
                                                        project_urn, \
                                                        credentials, \
                                                        {}, session)
                    if lookup_result['code'] != NO_ERROR:
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
                                raise CHAPIv1ArgumentError('New project lead %s not authorized to be a project lead' % (new_lead_urn))
                            new_project_lead = row['PROJECT_MEMBER_UID']
                            break

#                    q = session.query(self.db.MEMBER_ATTRIBUTE_TABLE.c.value).\
#                    filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.member_id == new_project_lead).\
#                    filter(self.db.MEMBER_ATTRIBUTE_TABLE.c.name == 'PROJECT_LEAD')
#                    rows = q.all()
#                    if len(rows) == 0 or rows[0][0] != 'true':
#                        raise CHAPIv1ArgumentError('New project lead not authorized')


        result = self.modify_membership(client_cert, session, ProjectMember, client_uuid, \
                                          project_id, project_urn, \
                                          credentials, options, 'project_id', \
                                          'PROJECT_MEMBER', 'PROJECT_ROLE', \
                                          'project')

        # identify all slices in project and new project lead
        q = session.query(self.db.SLICE_TABLE)
        q = q.filter(self.db.SLICE_TABLE.c.project_id == project_id)
        q = q.filter(self.db.SLICE_TABLE.c.expired == False) # We only care about active slices
        project_slices = q.all()
    
        slice_uids = [row.slice_id for row in project_slices]
        slice_urns = {}
        for row in project_slices:
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
                                 project_lead_urn, credentials, {}, session)

            # change lead's role on slices he/she is member of
            for slice in result3['value']:
                # skip slice if not in current project
                if slice['SLICE_UID'] not in slice_uids:
                    continue
                del(slice_urns[slice['SLICE_UID']])
                if slice['SLICE_ROLE'] not in ['LEAD', 'ADMIN']:
                    lead_options = {'members_to_change': opt}
                    lead_options.update(speaking_for)
                    self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                           slice['SLICE_UID'], slice['SLICE_URN'], credentials, lead_options, \
                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')
                    
            # add lead to slices not yet a member of
            for slice_id, slice_urn in slice_urns.iteritems():
                 lead_options2 = {'members_to_add': opt}
                 lead_options2.update(speaking_for)
                 self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                           slice_id, slice_urn, credentials, lead_options2, \
                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

        # now delete all removed members from slices
        if 'members_to_remove' in options:
            for member in options['members_to_remove']:
                result3 = self.lookup_slices_for_member(client_cert, member, \
                                                        credentials, {}, session)
                for slice in result3['value']:
                    # skip slices that are not part of the current project
                    if not slice['SLICE_UID'] in slice_uids:
                        continue
                    del_options = {'members_to_remove': [member]}
                    del_options.update(speaking_for)

                    # if member is lead on the slice, make a new lead
                    if slice['SLICE_ROLE'] == 'LEAD':
                        opt = [{'SLICE_MEMBER': project_lead_urn,
                                'SLICE_ROLE': 'LEAD'}]
                        q = session.query(SliceMember.member_id)
                        q = q.filter(SliceMember.slice_id == slice['SLICE_UID'])
                        q = q.filter(SliceMember.member_id == project_lead)
                        if len(q.all()) > 0:
                            del_options['members_to_change'] = opt
                        else:
                            del_options['members_to_add'] = opt

                        # Also, change the slice owner_id
                        q = session.query(Slice)
                        q = q.filter(Slice.slice_id == slice['SLICE_UID'])
                        q = q.update({"owner_id" : project_lead})

                    self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                             slice['SLICE_UID'], slice['SLICE_URN'], credentials, del_options, \
                             'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

        # All new project admins should be admins in all project slices
        if 'members_to_add' in options:
            for member in options['members_to_add']:
                # If the new member has role of admin, then we need to ensure they are
                # an admin on all slices in the project
                if member['PROJECT_ROLE'] == 'ADMIN':
                    # For each slice in project
                    for slice in project_slices:
                        q = session.query(SliceMember.role)
                        q = q.filter(SliceMember.slice_id == slice.slice_id)
                        q = q.filter(SliceMember.member_id == self.get_member_id_for_urn(session, member['PROJECT_MEMBER']))
                        if q.count() <= 0:
                            nopt = [{'SLICE_MEMBER': member['PROJECT_MEMBER'], 'SLICE_ROLE': 'ADMIN'}]
                            noptions = {'members_to_add': nopt}
                            noptions.update(speaking_for)
                            self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                                                       slice.slice_id, slice.slice_urn, credentials, noptions, \
                                                       'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')
                        else:
                            # If the new admin is a member or auditor on the slice, make them an admin on the slice
                            # check SliceMember.role
                            row = q.one()
                            if row[0] == self.get_role_id(session, 'MEMBER') or row[0] == self.get_role_id(session, 'AUDITOR'):
                                nopt = [{'SLICE_MEMBER': member['PROJECT_MEMBER'], 'SLICE_ROLE': 'ADMIN'}]
                                noptions = {'members_to_change': nopt}
                                noptions.update(speaking_for)
                                self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                                                           slice.slice_id, slice.slice_urn, credentials, noptions, \
                                                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')

        if 'members_to_change' in options:
            for member in options['members_to_change']:
                # If the new member has role of admin, then we need to ensure they are
                # an admin on all slices in the project
                if member['PROJECT_ROLE'] == 'ADMIN':
                    # For each slice in project
                    for slice in project_slices:
                        q = session.query(SliceMember.role)
                        q = q.filter(SliceMember.slice_id == slice.slice_id)
                        q = q.filter(SliceMember.member_id == self.get_member_id_for_urn(session, member['PROJECT_MEMBER']))
                        if q.count() <= 0:
                            nopt = [{'SLICE_MEMBER': member['PROJECT_MEMBER'], 'SLICE_ROLE': 'ADMIN'}]
                            noptions = {'members_to_add': nopt}
                            noptions.update(speaking_for)
                            self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                                                       slice.slice_id, slice.slice_urn, credentials, noptions, \
                                                       'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')
                        else:
                            # If the new admin is a member or auditor on the slice, make them an admin on the slice
                            # check SliceMember.role
                            row = q.one()
                            if row[0] == self.get_role_id(session, 'MEMBER') or row[0] == self.get_role_id(session, 'AUDITOR'):
                                nopt = [{'SLICE_MEMBER': member['PROJECT_MEMBER'], 'SLICE_ROLE': 'ADMIN'}]
                                noptions = {'members_to_change': nopt}
                                noptions.update(speaking_for)
                                self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                                                           slice.slice_id, slice.slice_urn, credentials, noptions, \
                                                           'slice_id', 'SLICE_MEMBER', 'SLICE_ROLE', 'slice')


        return result

    # change the membership in a slice
    def modify_slice_membership(self, client_cert, slice_urn, \
                                credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_slice_expirations(client_uuid, session)

        slice_id = self.get_slice_id(session, "slice_urn", slice_urn) # MIK: only non-expired slice
        if slice_id is None:
            # No unexpired slice by that URN, so cannot modify membership
            raise CHAPIv1ArgumentError('Cannot modify membership of expired slice %s' % slice_urn)
        old_slice_lead = self.get_slice_lead(session, slice_id)

        result = self.modify_membership(client_cert, session, SliceMember, client_uuid, \
                                          slice_id, slice_urn, \
                                          credentials, options, 'slice_id', \
                                          'SLICE_MEMBER', 'SLICE_ROLE', \
                                          'slice')
        
        # Validate that new slice lead is not a project auditor
        new_slice_lead = self.get_slice_lead(session,slice_id)
        new_lead_urn = self.get_member_urn_for_id(session, new_slice_lead)
        # get project id
        q = session.query(Slice.project_id)
        q = q.filter(Slice.slice_id == slice_id)
        slice_row = q.one()

        rows = self.lookup_for_member(new_lead_urn, self.db.PROJECT_TABLE, \
                  self.db.PROJECT_MEMBER_TABLE, "project_name", "project_id", 
                                      session)
        projects = [{"PROJECT_ROLE" : row.name, \
                         "PROJECT_UID" : row.project_id, \
                         "PROJECT_URN": row_to_project_urn(row), \
                         "EXPIRED" : row.expired } \
                        for row in rows]
        role = None
        for proj in projects:
            if proj['PROJECT_UID'] == slice_row.project_id:
                role = proj['PROJECT_ROLE']
                break

        if role == 'AUDITOR':
            raise CHAPIv1ArgumentError('Cannot make a project auditor a slice lead')
        
        # if slice lead has changed, change in sa_slice table
        if new_slice_lead != old_slice_lead:
            q = session.query(Slice)
            q = q.filter(Slice.slice_id == slice_id)
            q = q.update({"owner_id" : new_slice_lead})
            

        return result

    # shared between modify_slice_membership and modify_project_membership
    def modify_membership(self, client_cert, session, member_class, client_uuid, id, urn, 
                          credentials, options, id_field,
                          member_str, role_str, text_str):

        user_email = get_email_from_cert(client_cert)
        id_str = '%s.%s' % (member_class.__name__, id_field)

        # Grab the display names and IDs for all members whose membership we are changing
        all_urns = []
        if 'members_to_add' in options: 
            for member_to_add in options['members_to_add']:
                all_urns.append(member_to_add[member_str])
        if 'members_to_remove' in options: 
            for member_to_remove in options['members_to_remove']:
                all_urns.append(member_to_remove)
        if 'members_to_change' in options: 
            for member_to_change in options['members_to_change']:
                all_urns.append(member_to_change[member_str])
#        chapi_info('SA', "ALL_URNS = %s" % all_urns)

        # Also get the caller's pretty name
        caller_urn = get_urn_from_cert(client_cert)
        all_urns.append(caller_urn)

        lookup_identifying_options = {\
            "match" : {"MEMBER_URN" : all_urns}, 
            "filter" : ["_GENI_MEMBER_DISPLAYNAME", "MEMBER_FIRSTNAME", 
                        "MEMBER_LASTNAME", "MEMBER_EMAIL", "_GENI_IDENTIFYING_MEMBER_UID"]}
        ma_handler = pm.getService('mav1handler')
        result = ma_handler._delegate.lookup_identifying_member_info(client_cert, credentials, lookup_identifying_options, session)
        urn_to_display_name = {}
        urn_to_id = {}
        # If we failed to get the display names, use the usernames
        for member_urn in all_urns:
            if result['code'] != NO_ERROR or member_urn not in result['value']:
                urn_to_display_name[member_urn] = \
                    get_name_from_urn(member_urn)
            else:
                urn_to_display_name[member_urn] = \
                    get_member_display_name(result['value'][member_urn], member_urn)
                urn_to_id[member_urn] = result['value'][member_urn]["_GENI_IDENTIFYING_MEMBER_UID"]
        chapi_debug('SA:MA', "URN_TO_DISPLAY_NAME = %s" % urn_to_display_name)

        # first, do the removes
        if 'members_to_remove' in options and len(options['members_to_remove']) > 0:
            q = session.query(member_class)
            ids = [urn_to_id[m_urn] for m_urn in options['members_to_remove']]
            if len(ids) > 0:
                q = q.filter(member_class.member_id.in_(ids))
                q = q.filter(eval(id_str) == id)
                q.delete(synchronize_session='fetch')

        # then, do the additions
        if 'members_to_add' in options:
            for member in options['members_to_add']:
                member_obj = member_class()
                setattr(member_obj, id_field, id)
                if not urn_to_id.has_key(member[member_str]):
                    raise CHAPIv1ArgumentError('No such member ' + \
                        member[member_str])
                member_obj.member_id = urn_to_id[member[member_str]]
                if not member_obj.member_id:
                    raise CHAPIv1ArgumentError('No such member ' + \
                        member[member_str])

                # If this is an addition to a slice, first validate
                # that the member is a member of the relevant project
                if member_str == 'SLICE_MEMBER':
                    q = session.query(ProjectMember, Slice)
                    q = q.filter(Slice.slice_id == id)
                    q = q.filter(Slice.project_id == ProjectMember.project_id)
                    q = q.filter(ProjectMember.member_id == member_obj.member_id)
                    if len(q.all()) == 0:
                        raise CHAPIv1ArgumentError("Cannot add member to slice when not in project. Member %s not in project for slice %s" % (urn_to_display_name[member[member_str]], urn))

                member_obj.role = self.get_role_id(session, member[role_str])
                if member_obj.role is None:
                    raise CHAPIv1ArgumentError("Unknown role %s. Cannot add member %s to %s" % (member[role_str],
                                                                                                member[member_str],
                                                                                                text_str))
                session.add(member_obj)
                # check that this is not a duplicate
                q = session.query(member_class)
                q = q.filter(eval(id_str) == id)
                q = q.filter(member_class.member_id == member_obj.member_id)
                if len(q.all()) > 1:
                    raise CHAPIv1DuplicateError('Member ' + \
                        member[member_str] + ' already in ' + text_str)

        # then, the updates
        if 'members_to_change' in options:
            for member in options['members_to_change']:
                if not urn_to_id.has_key(member[member_str]):
                    raise CHAPIv1ArgumentError('No such member ' + \
                        member[member_str])
                q = session.query(member_class)
                q = q.filter(eval(id_str) == id)
                q = q.filter(member_class.member_id == \
                    urn_to_id[member[member_str]])
                if len(q.all()) == 0:
                    raise CHAPIv1ArgumentError('Cannot change role of member ' + \
                             member[member_str] + ' not in ' + text_str)
                role = self.get_role_id(session, member[role_str])
                if role is None:
                    raise CHAPIv1ArgumentError("Unknown role %s. Cannot change member %s role in %s" % (member[role_str],
                                                                                                member[member_str], text_str))
                q.update({"role" : role})

        # before committing, check that there is exactly one lead
        q = session.query(member_class)
        q = q.filter(eval(id_str) == id)
        q = q.filter(member_class.role == self.get_role_id(session, "LEAD"))
        num_leads = len(q.all())
        if num_leads != 1:
            raise CHAPIv1ArgumentError('Cannot modify membership: this would result in ' + \
                          str(num_leads) + ' leads for the ' + text_str)


        # Now log the removals, adds, changes

        # Get attributes for logging membership changes
        if text_str == 'slice':
            project_name, authority, slice_name = \
                extract_data_from_slice_urn(urn)
            project_id = \
                self.get_project_id(session, 'project_name', project_name)
            attribs = {"SLICE" : id, "PROJECT" : project_id}
            label = slice_name
            label2 = "%s in project %s" % (slice_name, project_name)
        else:
            project_name = get_name_from_urn(urn)
            attribs = {"PROJECT" : id}
            label = project_name
            label2 = label

        # Log all removals
        if 'members_to_remove' in options:
            members_to_remove = options['members_to_remove']
            for member_to_remove in members_to_remove:
                member_name = urn_to_display_name[member_to_remove]
                attribs["MEMBER"] = urn_to_id[member_to_remove]
                self.logging_service.log_event(
                    "Removed member %s from %s %s" % \
                        (member_name, text_str, label), \
                        attribs, credentials, options, session=session)
                chapi_info(SA_LOG_PREFIX, "Removed member %s from %s %s" % (member_name, text_str, label2), {'user': user_email})

        # Log all adds
        if 'members_to_add' in options:
            caller_name = urn_to_display_name[caller_urn]
            members_to_add = options['members_to_add']
            for member_to_add in members_to_add:
                member_urn = member_to_add[member_str]
                member_name = urn_to_display_name[member_urn]
                member_role = member_to_add[role_str]
                attribs["MEMBER"] = urn_to_id[member_urn]
                if caller_urn == member_urn:
                    self.logging_service.log_event(
                        "%s accepted an invitation to join %s %s in role %s" % \
                            (member_name, text_str, label, member_role), 
                        attribs, credentials, options, session=session)
                    chapi_audit_and_log(SA_LOG_PREFIX, 
                                        "%s accepted an invitation to join %s %s in role %s" % \
                                            (member_name, text_str, label2, member_role), logging.INFO, {'user': user_email})
                else:
                    self.logging_service.log_event(
                        "%s Added member %s in role %s to %s %s" % \
                            (caller_name, member_name, member_role, text_str, label), 
                        attribs, credentials, options, session=session)
                    chapi_audit_and_log(SA_LOG_PREFIX, 
                                        "%s Added member %s in role %s to %s %s" % \
                                            (caller_name, member_name, member_role, text_str, label2), logging.INFO, {'user': user_email})
                # Email system admins about new project members
                if text_str == 'project':
                    subject = "New GENI CH project member added"
                    if caller_urn == member_urn:
                        msgbody = "%s accepted an invitation to join project %s in role %s on CH %s" % \
                            (member_name, label, member_role, self.config.get("chrm.authority"))
                    else:
                        msgbody = "%s added member %s in role %s to project %s on CH %s" % \
                            (caller_name, member_name, member_role, label, self.config.get("chrm.authority"))
                    to_list = [self.portal_admin_email]
                    send_email(to_list, self.ch_from_email, self.portal_admin_email, subject, msgbody)

        # Log all changes
        if 'members_to_change' in options:
            members_to_change = options['members_to_change']
            for member_to_change in members_to_change:
                member_urn = member_to_change[member_str]
                member_name = urn_to_display_name[member_urn]
                member_role = member_to_change[role_str]
                attribs["MEMBER"] = urn_to_id[member_urn]
                self.logging_service.log_event(
                    "Changed member %s to role %s in %s %s" % \
                        (member_name, member_role, text_str, label), 
                        attribs, credentials, options, session=session)
                chapi_info(SA_LOG_PREFIX, "Changed member %s to role %s in %s %s" % (member_name, member_role, text_str, label2), {'user': user_email})

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
        if role is None or str(role).strip() == "":
            return None
        q = session.query(self.db.ROLE_TABLE.c.id)
        q = q.filter(self.db.ROLE_TABLE.c.name == str(role).upper())
        rows = q.all()
        if len(rows) > 0:
           return rows[0].id
        return None

    # Lookup attributes for project
    def lookup_project_attributes(self, client_cert, project_urn, \
                                      credentials, options, session):
        method = 'lookup_project_attributes'
        args = {'project_urn' : project_urn}

        client_uuid = get_uuid_from_cert(client_cert)
        self.update_project_expirations(client_uuid, session)

        name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, "project_name", name)
        q = session.query(self.db.PROJECT_ATTRIBUTE_TABLE )
        q = q.filter(self.db.PROJECT_ATTRIBUTE_TABLE.c.project_id==project_id)
        rows = q.all()
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

    def expire_sliver_infos(self, session):
        # Delete expired sliver_info entries
        q = session.query(SliverInfo)
        # Find all sliver info entries that expired x minutes ago 
        gracemin = 6 # FIXME: Externalize this
        q = q.filter(and_(SliverInfo.expiration != None, SliverInfo.expiration < text("now() at time zone 'utc' - INTERVAL '%d MINUTE'" % gracemin)))
        if q.count() > 0:
            chapi_info(SA_LOG_PREFIX, "Deleting %d expired sliver_info records" % q.count())
            q.delete(synchronize_session='fetch')

    def create_sliver_info(self, client_cert, credentials, options, session):
        self.expire_sliver_infos(session)
        sliver = SliverInfo()
        for field, value in options['fields'].iteritems():
           setattr(sliver, SA.sliver_info_field_mapping[field], value)

        # API spec says this field is optional, and we do not know that it was just created
#        if not sliver.creation:
#            sliver.creation = datetime.utcnow()

#        # Surprisingly, the API spec says this field is optional
#        if not sliver.expiration:
#            if sliver.creation:
#                sliver.expiration = sliver.creation + relativedelta(days=7) # FIXME: Externalize
#            else:
#                sliver.expiration = datetime.utcnow() + relativedelta(days=7) # FIXME: Externalize

        # API spec says this field is not optional
        if not sliver.creator_urn:
            raise CHAPIv1ArgumentError("Missing creator_urn from sliver_info record")
#            sliver.creator_urn = get_urn_from_cert(client_cert)

        # If there is already a sliver_info record with the same sliver_urn,
        # Then treat this as an update instead of a create. 
        # This might happen if the last sliver was recorded with no expiration time,
        # and the sliver_info was never explicitly deleted.
        # Note that sliver urns are unique over time per the spec,
        # so this shouldn't really happen.
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver.sliver_urn)
        user_email = get_email_from_cert(client_cert)
        if q.count() > 0:
            # FIXME: If the existing row has a different slice urn or agg urn, then what?
            # If the existing row has an expiration that we have not reached, then what?
            chapi_debug(SA_LOG_PREFIX, "Create sliver info for %s found record exists - doing update" % sliver.sliver_urn, {'user': user_email})
            return self.update_sliver_info(client_cert, sliver.sliver_urn, credentials, options, session)

#        chapi_debug(SA_LOG_PREFIX, "Created sliver info for %s" % sliver.sliver_urn, {'user': user_email})
        return self.finish_create(session, sliver, SA.sliver_info_field_mapping)

    def delete_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options, session):
        self.expire_sliver_infos(session)
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver_urn)
        delCount = q.count()
        if delCount < 1:
            raise CHAPIv1ArgumentError("Unknown sliver urn %s - cannot delete sliver info record" % sliver_urn)
        q.delete(synchronize_session='fetch')
        user_email = get_email_from_cert(client_cert)
        chapi_debug(SA_LOG_PREFIX, "Deleted %d sliver info records for sliver %s" % (delCount, sliver_urn), {'user': user_email})
        # API says return True if succeeded
        return self._successReturn(True)

    def update_sliver_info(self, client_cert, sliver_urn, \
                               credentials, options, session):
        q = session.query(SliverInfo)
        q = q.filter(SliverInfo.sliver_urn == sliver_urn)

        if q.count() == 0:
#            # The sliver is not recorded yet.
#            # The API says this should be an ArgumentError

#            # If the options include the AM URN and slice urn (which the spec says is not allowed), do the create anyhow?
#            if options.has_key('fields') and options['fields'].has_key('SLIVER_INFO_SLICE_URN') and options['fields'].has_key('SLIVER_INFO_AGGREGATE_URN'):
#                options['fields']['SLIVER_INFO_URN'] = sliver_urn

#                # FIXME: This urn for the creator could be correct but no guarantees. But
#                # Update doesn't take creator and create requires it.
#                options['fields']['SLIVER_INFO_CREATOR_URN'] = get_urn_from_cert(client_cert)
#                return self.create_sliver_info(client_cert, credentials, options, session)
#            else:
            raise CHAPIv1ArgumentError("Unknown sliver urn %s - cannot update sliver info record" % sliver_urn)

        vals = {}
        for field, value in options['fields'].iteritems():
           vals[SA.sliver_info_field_mapping[field]] = value
        updateCount = q.update(vals)
        user_email = get_email_from_cert(client_cert)
        chapi_debug(SA_LOG_PREFIX, "Updated %d sliver info records for sliver %s" % (updateCount, sliver_urn), {'user': user_email})
        self.expire_sliver_infos(session)
        # API says return: None
        return self._successReturn(True)

    def lookup_sliver_info(self, client_cert, credentials, options, session):
        columns, match_criteria = \
            unpack_query_options(options, SA.sliver_info_field_mapping)
        q = session.query(self.db.SLIVER_INFO_TABLE)
        q = add_filters(q, match_criteria, self.db.SLIVER_INFO_TABLE, \
                        SA.sliver_info_field_mapping, session)

        # Hide any expired slivers (expired at least X minutes ago)
        gracemin = 0 # FIXME: externalize this
        q = q.filter(or_(SliverInfo.expiration == None, SliverInfo.expiration > text("now() at time zone 'utc' - INTERVAL '%d MINUTE'" % gracemin)))

        # Note we do not expire slivers cause the session for this method is read-only

        rows = q.all()
        slivers = {}
        for row in rows:
            slivers[row.sliver_urn] = \
                construct_result_row(row, columns, \
                                         SA.sliver_info_field_mapping, session)
        return self._successReturn(slivers)


    # Methods for managing pending project requests

    def create_request(self, client_cert, context_type, \
                           context_id, request_type, request_text, \
                           request_details, credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)

        # Ticket 187: Check for an existing request in state pending
        # with the same context_type, context_id, request_type,
        # and requestor. Ignore this request if there is one.
        q = session.query(self.db.PROJECT_REQUEST_TABLE.c.id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type
                     == context_type)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.request_type
                     == request_type)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.requestor == client_uuid)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == PENDING_STATUS)
        if q.count() > 0:
            # log an error message
            user_email = get_email_from_cert(client_cert)
            msg = "Ignoring duplicate project join request to join %s."
            msg = msg % (context_id)
            chapi_info(SA_LOG_PREFIX, msg, {'user': user_email})
            # return the ID of an existing request
            # use 'all' instead of 'one' in case there are multiple
            # existing requests.
            rows = q.all()
            return self._successReturn(rows[0].id)

        ins = self.db.PROJECT_REQUEST_TABLE.insert().values(
            context_type = context_type, \
                context_id = context_id, \
                request_type = request_type, \
                request_text = request_text, \
                request_details = request_details, \
                creation_timestamp = dt.datetime.utcnow(), \
                status = PENDING_STATUS, \
                requestor = client_uuid)
        result = session.execute(ins)
        
        query = "select max(id) from pa_project_member_request"
        request_id  = session.execute(query).fetchone().values()[0]
        result = self._successReturn(request_id)

        return result


    def resolve_pending_request(self, client_cert, context_type, request_id, \
                                    resolution_status, resolution_description,  \
                                    credentials, options, session):

        client_uuid = get_uuid_from_cert(client_cert)

        # check that request is still pending
        q = session.query(self.db.PROJECT_REQUEST_TABLE.c.status)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        status_info = q.one()
        if not status_info.status == PENDING_STATUS:
            raise CHAPIv1ArgumentError("Request %s is no longer pending" % str(request_id))
        
        update_values = {'status' : resolution_status, 
                         'resolver' : client_uuid, 
                         'resolution_description' : resolution_description,
                         'resolution_timestamp' : dt.datetime.utcnow() 
                         }
        update = self.db.PROJECT_REQUEST_TABLE.update(values=update_values)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        update = update.where(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        session.execute(update)
        result = self._successReturn(True)

        return result

    def get_requests_for_context(self, client_cert, context_type, \
                                 context_id, status, \
                                 credentials, options, session):

        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        if status:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == status)
        rows = q.all()
        result = [construct_result_row(row, SA.project_request_columns, 
                                       SA.project_request_field_mapping, 
                                       session) \
                      for row in rows]
        result = self._successReturn(result)

        return result

    def get_requests_by_user(self, client_cert, member_id, context_type, \
                                 context_id, status, \
                                 credentials, options, session):

        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        if context_id:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_id == context_id)
        if status or status == 0:
            q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.status == status)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.requestor == member_id)

        rows = q.all()
#        print "ROWS = " + str(rows)
        result = [construct_result_row(row, SA.project_request_columns, 
                                       SA.project_request_field_mapping,
                                       session) \
                      for row in rows]

        return self._successReturn(result)

    def get_pending_requests_for_user(self, client_cert, member_id, \
                                          context_type, context_id, \
                                          credentials, options, session):

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
#        print "ROWS = " + str(rows)
        result = [construct_result_row(row, SA.project_request_columns, 
                                       SA.project_request_field_mapping,
                                       session) \
                      for row in rows]
        result = self._successReturn(result)

        return result

    def get_number_of_pending_requests_for_user(self, client_cert, member_id, \
                                                    context_type, context_id, \
                                                    credentials, options,
                                                session):

        requests = self.get_pending_requests_for_user(client_cert, member_id, \
                                                          context_type, context_id,  \
                                                          credentials, 
                                                      options, session)
        if requests['code'] != NO_ERROR:
            return requests
        result = self._successReturn(len(requests['value']))

        return result


    def get_request_by_id(self, client_cert, request_id, context_type, \
                              credentials, options, session):

        q = session.query(self.db.PROJECT_REQUEST_TABLE)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.id == request_id)
        q = q.filter(self.db.PROJECT_REQUEST_TABLE.c.context_type == context_type)
        rows = q.all()
        if len(rows) == 0:
            return self._successReturn(None)
        result = \
            self._successReturn(construct_result_row(rows[0], 
                                                     SA.project_request_columns, 
                                                     SA.project_request_field_mapping,
                                                     session))

        return result

    # Add an attribute to a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name, 'attr_value' : attr_value}
    def add_project_attribute(self, \
                                  client_cert, project_urn, \
                                  credentials, options, session):
        if not options or 'attr_name' not in options or 'attr_value' not in options:
            raise CHAPIv1ArgumentError("Missing attribute name/value for add_project_attribute")

        attr_name = options['attr_name']
        attr_value = options['attr_value']

        project_name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, 'project_name', project_name)

        ins = self.db.PROJECT_ATTRIBUTE_TABLE.insert().values(project_id = project_id, 
                                                              name = attr_name, 
                                                              value = attr_value)

        session.execute(ins)
        result = True

        return self._successReturn(result)

    # remove an attribute from a given project
    # arguments: project_urn
    #     options {'attr_name' : attr_name}
    def remove_project_attribute(self, \
                                     client_cert, project_urn, \
                                     credentials, options, session):
        if not options or 'attr_name' not in options:
            raise CHAPIv1ArgumentError("Missing attribute name/value for remove_project_attribute")
        attr_name = options['attr_name']

        project_name = from_project_urn(project_urn)
        project_id = self.get_project_id(session, 'project_name', project_name)

        q = session.query(ProjectAttribute)
        q = q.filter(ProjectAttribute.project_id == project_id)
        q = q.filter(ProjectAttribute.name == attr_name)

        q.delete(synchronize_session='fetch')
        result = True

        return self._successReturn(result)

    # Invite a member to join a project in a given role
    def invite_member(self, client_cert, role, project_id, 
                      credentials, options, session):

        # Set expiration
        # insert into PA_PROJECT_MEMBER_INVITATION 
        #    (project_id, role, expiration) values 
        #    (project_id, role, expiration)
        # Extract and return invite_id

        self._expire_project_invitations(session)

        invite_id = str(uuid.uuid4())
        expiration = dt.datetime.utcnow() + relativedelta(hours=SA.PROJECT_DEFAULT_INVITATION_EXPIRATION_HOURS)
        ins = self.db.PROJECT_INVITATION_TABLE.insert().values(expiration=expiration, project_id=project_id, role=role, invite_id=invite_id)
        session.execute(ins)

        result = {'expiration' : str(expiration), 'invite_id' : invite_id}

        return self._successReturn(result)


    # Accept an invitation to join a project
    def accept_invitation(self, client_cert, invite_id, member_id,
                          credentials, options, session):

        self._expire_project_invitations(session)

        # select project_id, role, expiration from 
        # PA_PROJECT_MEMBER_INVITATION where invite_id = invite_id
        q = session.query(ProjectInvitation)
        q = q.filter(ProjectInvitation.invite_id == invite_id)
        rows = q.all()

        # If no such (unexpired) invitation, return error
        if len(rows) < 1:
            raise CHAPIv1ArgumentError("No current invitation with given invite_id %s to accept" % invite_id)
        invite_info = rows[0]
        project_id = invite_info.project_id
        role = invite_info.role

        project_urn = convert_project_uid_to_urn(project_id, session)
        member_urn = convert_member_uid_to_urn(member_id, session)
        role_name = attribute_type_names[role]

        # Add the member to the project
        options = {'members_to_add' : [
                {"PROJECT_MEMBER" : member_urn, 
                 "PROJECT_ROLE" : role_name}
                ]}
        result = self.modify_project_membership(client_cert, project_urn, credentials, options, session)

        # Delete the invitation:
        session.delete(invite_info)

        return self._successReturn(result)

    # Remove all project invitations that whose expiration has passed
    def _expire_project_invitations(self, session):

        now = dt.datetime.utcnow()
        q = session.query(ProjectInvitation)
        q = q.filter(ProjectInvitation.expiration < now)
#        chapi_debug(SA_LOG_PREFIX, "expire_project_invitations Q = %s" % str(q))
        rows = q.all()
        for row in rows:
            chapi_info(SA_LOG_PREFIX, 'Expiring project invitation ID %s Project %s role %s' % \
                           (row.invite_id, row.project_id, row.role))
            session.delete(row)



