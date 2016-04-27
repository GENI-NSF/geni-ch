#----------------------------------------------------------------------
# Copyright (c) 2011-2016 Raytheon BBN Technologies
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

import json
import time
import datetime
import logging
import tools.pluginmanager as pm
from  sqlalchemy import *
from  sqlalchemy.orm import aliased
from tools.dbutils import STANDARD_DATETIME_FORMAT

opsmon_logger = logging.getLogger('opsmon')

# Replace : and + in URN to -                                            
def flatten(urn):
    return urn.replace(':', '_').replace('+', '_')

# Generate a URL for given authority, object type and ID
def generate_urn(authority, obj_type, obj_id):
    return "urn:publicid+IDN+%s+%s+%s" % (authority, obj_type, obj_id)

# Extract the enty name (last) portion from a urn
def extract_name_from_urn(urn):
    return urn.split('+')[-1]


# Class to handle Ops-mon (/info/<slice, authority, user>/<id> REST requests
class OpsMonHandler:

    # Schemas for different types of entries provided by this server
    _authority_schema = \
        "http://www.gpolab.bbn.com/monitoring/schema/20140828/authority#"
    _slice_schema = \
        "http://www.gpolab.bbn.com/monitoring/schema/20140828/slice#"
    _user_schema = \
        "http://www.gpolab.bbn.com/monitoring/schema/20140828/user#"

    # class variables
    _instance = None # Singleton instance

    # Constructor. Since we manage a singleton instance, should
    # be only called once (or at least be idempotent)
    def __init__(self):
        # Capture singleton instance
        OpsMonHandler._instance = self
        config = pm.getService('config')
        authority = config.get('chrm.authority')
        self._base_url = "https://%s" % authority
        self._authority = authority
        self._authority_urn = generate_urn(authority, 'authority', 'ch')
        self._authority_href = self.generate_href('authority', authority)
        self._db = pm.getService('chdbengine')

    # Generate an HREF for given object type and ID
    def generate_href(self, obj_type, obj_id):
        return "%s/info/%s/%s" % (self._base_url, obj_type, obj_id)

    # Return portion of URN after the IDN+
    def truncate_urn(self, urn):
        return '+'.join(urn.split('+')[1:])

    # For a given URN and object type 
    # (and optional ID, otherwise derived from URN)
    # Return a dictionary of object URN, href and ID 
    def compute_reference_info(self, urn, obj_type, obj_id = None):
        if obj_id is None:
            obj_id = flatten(self.truncate_urn(urn))
        href = self.generate_href(obj_type, obj_id)
#        return {'urn' : urn, 'href' : href, 'id' : obj_id}
        return {'urn' : urn, 'href' : href}

    # Turn a datetime into a timestamp (microseconds since 1-1-1970
    def to_timestamp(self, dt):
        return int(time.mktime(dt.timetuple()) * 1000000)

    # Convert a slice_urn to slice_id by flattening the part after IDN+
    def slice_urn_to_id(self, slice_urn):
        return flatten(self.truncate_urn(slice_urn))

    # Convert a slice_id to slice_urn by splitting into parts, recombining
    # and adding the prefix
    # Assumes ID is of form <auth>_<project>_slice_<slice>
    def slice_id_to_urn(self, slice_id):
        slice_parts = slice_id.split('_slice_')
        slice_name = slice_parts[1]
        project_parts = slice_parts[0].split(self._authority + '_')
        project_name = project_parts[1]
        return "urn:publicid:IDN+%s:%s+slice+%s" % (self._authority, 
                                                    project_name, slice_name)

    # Return the opsmon information about this authority (only this one)
    # Return non-expired slices and their leads
    def handle_authority_request(self, auth_id, ts, session):

        opsmon_logger.info("Requested opsmon info for authority %s" % auth_id)

        if auth_id != self._authority:
            return ""

        # Grab URN's and leads of all unexpired slices
        q = session.query(self._db.SLICE_TABLE.c.slice_urn, 
                          self._db.SLICE_TABLE.c.slice_id, 
                          self._db.SLICE_TABLE.c.owner_id)
        q = q.filter(self._db.SLICE_TABLE.c.expired == 'f')
        rows = q.all()
        slices_info = [self.compute_reference_info(row.slice_urn, 'slice',
                                                   self.slice_urn_to_id(row.slice_urn))
                           for row in rows]

        # Grab URNs of all leads
        lead_uuids = [row.owner_id for row in rows]
        q = session.query(self._db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self._db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        if len(lead_uuids) > 0:
            q = q.filter(self._db.MEMBER_ATTRIBUTE_TABLE.c.member_id.in_(lead_uuids))
        else:
            q = q.filter(self._db.MEMBER_ATTRIBUTE_TABLE.c.member_id == None)
        rows = q.all()
        users_info = [self.compute_reference_info(row.value, 'user', 
                                                  row.value.split('+')[-1]) \
                          for row in rows]
                      
        authority_data = {
            "$schema" : self._authority_schema,
            "id" : self._authority,
            "selfRef" : self._authority_href,
            "urn" : self._authority_urn,
            "ts" : ts,
            "users" : users_info,
            "slices" : slices_info
            }
        return authority_data

    # Compute opsmon ifnormation about a given slice
    # slice_id is the flattened truncated URN:
    #    authority_projectname_slice_slicename
    def handle_slice_request(self, slice_id, ts, session):

        opsmon_logger.info("Requested opsmon info for slice %s" % slice_id)

        slice_urn = self.slice_id_to_urn(slice_id)

        q = session.query(self._db.SLICE_TABLE.c.creation,
                          self._db.SLICE_TABLE.c.expiration,
                          self._db.SLICE_TABLE.c.owner_id,
                          self._db.SLICE_TABLE.c.slice_id,
                          self._db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(self._db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        q = q.filter(self._db.MEMBER_ATTRIBUTE_TABLE.c.member_id == self._db.SLICE_TABLE.c.owner_id)
        q = q.filter(self._db.SLICE_TABLE.c.expired == 'f')
        q = q.filter(self._db.SLICE_TABLE.c.slice_urn == slice_urn)

        rows = q.all()
        if len(rows) == 0: return ""
        row = rows[0]
        slice_uuid = row.slice_id;

        lead_urn = row.value
        lead_id = extract_name_from_urn(lead_urn)
        lead_info = \
            self.compute_reference_info(lead_urn, 'user', lead_id)
        lead_info['role'] = 'lead'

        members = [lead_info]

        # As for all creators of current slivers in this slice
        q = session.query(self._db.SLIVER_INFO_TABLE.c.creator_urn).distinct()
        q = q.filter(self._db.SLIVER_INFO_TABLE.c.slice_urn == slice_urn)
        q = q.filter(self._db.SLIVER_INFO_TABLE.c.creator_urn != lead_urn)
        sliv_rows = q.all()
        for sliv_row in sliv_rows:
            member_urn = sliv_row.creator_urn
            member_id = extract_name_from_urn(member_urn)
            member_info = self.compute_reference_info(member_urn, 'user', member_id)
            member_info['role'] = 'member'
            members.append(member_info)

        slice_data = {
            '$schema' : self._slice_schema,
            'id' : self.slice_urn_to_id(slice_urn),
            'selfRef' : self.generate_href('slice', slice_id),
            'urn' : slice_urn,
            'uuid' : slice_uuid,
            'ts' : ts,
            'authority' : self.compute_reference_info(self._authority_urn, 
                                                      'authority',
                                                      self._authority),
            'created' : self.to_timestamp(row.creation),
            'expires' : self.to_timestamp(row.expiration),
            'members' : members
            }
        return slice_data

    # Generate the dictionary required for a given user by ID (username)
    def handle_user_request(self, user_id, ts, session):
        opsmon_logger.info("Requested opsmon info for user %s" % user_id)

        # Grab all attributes of user based on username
        ma1 = alias(self._db.MEMBER_ATTRIBUTE_TABLE)
        ma2 = alias(self._db.MEMBER_ATTRIBUTE_TABLE)
        q = session.query(ma2.c.name, ma2.c.value)

        q = q.filter(ma1.c.member_id == ma2.c.member_id)
        q = q.filter(ma1.c.name == 'username')
        q = q.filter(ma1.c.value == user_id)
        
        rows = q.all()
        if len(rows) == 0: return ""

        user_fullname = None
        user_firstname = None
        user_lastname = None
        user_email = None
        user_urn = None
        for row in rows:
            if row.name == 'displayName': user_fullname = row.value
            if row.name == 'email_address': user_email = row.value
            if row.name == 'first_name' : user_firstname = row.value
            if row.name == 'last_name' : user_lastname = row.value
            if row.name == 'urn' : user_urn = row.value

        if user_fullname is None:
            user_fullname = "%s %s" % (user_firstname, user_lastname)

        user_href = self.generate_href('user', user_id)

        user_data = {
            '$schema' : self._user_schema,
            'id' : user_id,
            'selfRef' : user_href,
            'urn' : user_urn,
            'ts' : ts,
            'authority' : \
                self.compute_reference_info(self._authority_urn, \
                                           'authority', self._authority),
            'fullname' : user_fullname,
            'email' : user_email
                }

        return user_data



    @staticmethod
    # Registered REST handler for handling a request on information
    # for object of given variety and ID
    def handle_opsmon_request(variety, id):
        id_data = ""
        opsmon = OpsMonHandler._instance
        session = opsmon._db.getSession()
        ts = int(time.time()*1000000)
        if variety == "authority":
            id_data = opsmon.handle_authority_request(id, ts, session)
        elif variety == "slice":
            id_data = opsmon.handle_slice_request(id, ts, session)
        elif variety == "user":
            id_data = opsmon.handle_user_request(id, ts, session)
        else:
            opsmon_logger.info("Unknown variety %s" % variety)

        session.close()
        
        return json.dumps(id_data)


