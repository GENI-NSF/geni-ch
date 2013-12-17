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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface

from CHDatabaseEngine import *
from chapi.DelegateBase import DelegateBase
from chapi.HandlerBase import HandlerBase
from chapi.Exceptions import *
from chapi.MethodContext import *
from ABACGuard import *

from tools.dbutils import *
from tools.geni_constants import *
from tools.chapi_log import *
from tools.cert_utils import get_email_from_cert
from tools.guard_utils import *

from sqlalchemy import *
from datetime import datetime
from dateutil.relativedelta import relativedelta


portal_logger = amsoil.core.log.getLogger('portalv1')
xmlrpc = pm.getService('xmlrpc')

class Portalv1Handler(HandlerBase):

    def __init__(self):
        super(Portalv1Handler, self).__init__(portal_logger)

    # Enter new logging entry in database for given sets of attributes
    # And logging user (author)
    def portal_query(self, member_eppn, project_id, slice_id):
        with MethodContext(self, PORTAL_LOG_PREFIX, 'portal_query',
                           {'member_eppn' : member_eppn,
                            'project_id' : project_id,
                            'slice_id' : slice_id},
                           [], {}, read_only=True, session=None) as mc:
            if not mc._error:
                mc._result = \
                    self._delegate.portal_query(mc._client_cert,
                                             member_eppn, project_id, slice_id,
                                             mc._session)
        return mc._result

class Portalv1Delegate(DelegateBase):

    def __init__(self):
        super(Portalv1Delegate, self).__init__(portal_logger)
        self._db = pm.getService('chdbengine')
        self._ch_handler = pm.getService('chv1handler')
        self._sa_handler = pm.getService('sav1handler')
        self._ma_handler = pm.getService('mav1handler')
        self._cs_handler = pm.getService('csv1handler')
        self._log_handler = pm.getService('loggingv1handler')

    # Get all information required for loading a standard portal page
    # consisting of member, slice, project information
    # including pending requests and log entries
    def portal_query(self, client_cert, member_eppn, project_id, 
                     slice_id, session):
        chapi_info(PORTAL_LOG_PREFIX, 
                   "*** In PQ *** M %s P %s S %s" % \
                       (member_eppn, project_id, slice_id))

        pq = PortalQuery(self._db,
                         self._ch_handler, self._sa_handler, self._ma_handler,
                         self._cs_handler, self._log_handler, client_cert)
        result = pq.run(member_eppn, project_id, slice_id, session)
        return self._successReturn(result)

class PortalQuery:
    def __init__(self, db, ch_handler, sa_handler, 
                 ma_handler, cs_handler, log_handler, 
                 client_cert):
        self._db = db
        self._ch_handler = ch_handler
        self._sa_handler = sa_handler
        self._ma_handler = ma_handler
        self._cs_handler = cs_handler
        self._log_handler = log_handler
        self._client_cert = client_cert

        # List of member uids for whom to grab public and identifying info
        self._pending_member_uids = [] 

        self._member_info_by_uid = {}
        self._slice_info_by_uid = {}
        self._project_info_by_uid = {}
        self._project_member_info_by_uid = {} # By project_id
        self._slice_info_by_uid = {}
        self._slice_member_info_by_uid = {} # By slice_id
        self._permissions = []
        self._pending_requests_for_member = []
        self._pending_requests_by_member = []
        self._log_entries = []

    def run(self, member_eppn, project_id, slice_id, session):
        

        # MA: Get private info for current member including UID
        member_private_info = \
            self._lookup_member_info('private', 
                                     {'_GENI_MEMBER_EPPN' : member_eppn },
                                     session)
        if  len(member_private_info) != 1:
            raise CHAPIv1ArgumentError("Invalid EPPN: " % member_eppn)
        member_urn = member_private_info.keys()[0]
        member_uid = member_private_info[member_urn]['_GENI_PRIVATE_MEMBER_UID']
        self._record_member_info(member_uid, member_private_info[member_urn])

        slices_for_member = []
        projects_for_member = []
        members_for_slice = []
        members_for_project = []

        # If project_id
        #    SA: Get project
        #    SA: Get project members for project
        #    SA: Get slices for project
        #    Grab all ID's of members and slice leads
        # else if slice_id
        #    SA: Get slice
        #    SA: Get slice members
        #    SA: Get slice project
        #    Grab all ID's of members and project lead
        # else (no slice or project specified)
        #    SA: Get Projects for member
        #    SA: Get Slices for member
        #    Grab all ID's of slice owners and project leads
        if project_id:
            project_info = \
                self._lookup_projects({'PROJECT_UID' : project_id}, session)
            project_urn = convert_project_uid_to_urn(project_id, session)
            members_for_project = \
                self._lookup_members(project_urn, False, session)
            slice_info = \
                self._lookup_slices({'SLICE_PROJECT_UID' : project_id}, 
                                    session)
            members_for_slice = [] # Don't need to extract this
        elif slice_id:
            slice_info = \
                self._lookup_slices({'SLICE_UID' : slice_id}, session)
            slice_urn = slice_info.keys()[0]
            members_for_slice = self._lookup_members(slice_urn, True, session)
            project_uid = slice_info[slice_urn]['_GENI_PROJECT_UID']
            project_urn = convert_project_uid_to_urn(project_uid, session)
            project_info = \
                self._lookup_projects({'PROJECT_UID' : project_uid}, 
                                      session)
            members_for_project = \
                self._lookup_members(project_urn, False, session)
        else:
            # No slice or project specified
            slices_for_member = \
                self._lookup_for_member(member_urn, True, session)
            slice_uids = self._grab_uids(slices_for_member, 'SLICE_UID')
            options = {'match' : {'SLICE_UID' : slice_uids}}
            slice_info = self._lookup_slices({'SLICE_UID' : slice_uids}, \
                                                 session)
            projects_for_member = \
                self._lookup_for_member(member_urn, False, session)
            project_uids = self._grab_uids(projects_for_member, 'PROJECT_UID')
            options = {'match' : {'PROJECT_UID' : project_uids}}
            project_info = self._lookup_projects(\
                {'PROJECT_UID' : project_uids}, session)
 
        # CS: Grab permissions
        #   For this member (context free)
        #   For this list of projects
        #   For this list of slices
        self._permissions = self._get_permissions(member_uid, session)

        # Register all the slice 
        for slice_urn, slice_data in slice_info.items():
            slice_uid = slice_data['SLICE_UID']
            self._slice_info_by_uid[slice_uid] = slice_data

        # Register all the project info
        for project_urn, project_data in project_info.items():
            project_uid = project_data['PROJECT_UID']
            self._project_info_by_uid[project_uid] = project_data

        # Register all project and slice members for future resolution
        for slice_member in members_for_slice:
            slice_member_uid = slice_member['SLICE_MEMBER_UID']
            self._record_member_info(slice_member_uid, {})
        for project_member in members_for_project:
            project_member_uid = project_member['PROJECT_MEMBER_UID']
            self._record_member_info(project_member_uid, {})

        # Register all project => members, slice => members
        for slice_member_info in slices_for_member:
            member_slice_id = slice_member_info['SLICE_UID']
            if member_slice_id not in self._slice_member_info_by_uid:
                self._slice_member_info_by_uid[member_slice_id] = []
            self._slice_member_info_by_uid[member_slice_id].append(slice_member_info)
        for project_member_info in projects_for_member:
            member_project_id = project_member_info['PROJECT_UID']
            if member_project_id not in self._project_member_info_by_uid:
                self._project_member_info_by_uid[member_project_id] = []
            self._project_member_info_by_uid[member_project_id].append(project_member_info)
        if slice_id:
            for slice_member_info in members_for_slice:
                if slice_id not in self._slice_member_info_by_uid:
                    self._slice_member_info_by_uid[slice_id] = []
                    self._slice_member_info_by_uid[slice_id].append(slice_member_info)
        if project_id:
            for project_member_info in members_for_project:
                if project_id not in self._project_member_info_by_uid:
                    self._project_member_info_by_uid[project_id] = []
                    self._project_member_info_by_uid[project_id].append(project_member_info)
            

        # SA: Get pending requests by user
        # SA: Get pending requests for user
        #  Grab ID's of all requestors
        self._get_project_requests(member_uid, project_id, slice_id, session)

        # LOG : Get log requets for context (member or project or slice)
        #    Grab ID's of all log writers
        self._log_entries = self._get_log_entries(member_uid, project_id, 
                                                  slice_id, session)
        for log_entry in self._log_entries:
            member_id = log_entry['user_id']
            self._record_member_info(member_id, {})

        # MA: Get public and identifying information for all referenced members
        self._resolve_pending_members(session)

        # Return
        # {'member_info' : member_info_by_uid,
        #  'project_info' : project_info_by_uid,
        #  'project_member_info' : project_member_info_by_uid
        #  'slice_Info' : slice_info_by_urn
        #  'slice_member_info' : slice_member_info_by_uid
        #  'permissions' : list of privileges for current user for given
        #     slices and privileges and other context-free operations
        #  'pending_requests_by_member' : 
        #    pending project_requests by current member
        #  'pending_requests_for_member' : 
        #    pending project_requests for current member
        #  'log_entries' : selected_log_entries
        result = {'member_info' :  self._member_info_by_uid,
                  'project_info' : self._project_info_by_uid,
                  'project_member_info' : self._project_member_info_by_uid,
                  'slice_info' : self._slice_info_by_uid,
                  'slice_member_info' : self._slice_member_info_by_uid,
                  'permissions' : self._permissions,
                  'pending_requests_for_member' : \
                      self._pending_requests_for_member,
                  'pending_requests_by_member' : \
                      self._pending_requests_by_member,
                  'log_entries' : self._log_entries}
        return result

    def _lookup_slices(self, match, session):
        chapi_info(PORTAL_LOG_PREFIX, "Invoking lookup_slices %s" % match)
        result = self._sa_handler._delegate.lookup_slices(\
            self._client_cert, [], {'match' : match}, session)
        chapi_info(PORTAL_LOG_PREFIX, "Result from lookup_slices %s" % result)
        return result['value']

    def _lookup_members(self, urn, for_slice, session):
        if for_slice:
            method = 'lookup_slice_members'
            result = self._sa_handler._delegate.lookup_slice_members(\
                self._client_cert,  urn, [], {}, session)
        else:
            method = 'lookup_project_members'
            result = self._sa_handler._delegate.lookup_project_members(\
                self._client_cert,  urn, [], {}, session)
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s" % (method, urn))
        chapi_info(PORTAL_LOG_PREFIX, "Result from %s %s" % (method, result))
        return result['value']

    def _lookup_projects(self, match, session):
        chapi_info(PORTAL_LOG_PREFIX, "Invoking lookup_projects %s" % match)
        result = self._sa_handler._delegate.lookup_projects(\
            self._client_cert, [], {'match' : match}, session)
        chapi_info(PORTAL_LOG_PREFIX, "Result from lookup_projects %s" % result)
        return result['value']

    def _lookup_for_member(self, member_urn, for_slice, session):
        if for_slice:
            method = 'lookup_slices_for_member'
            result = self._sa_handler._delegate.lookup_slices_for_member(\
                self._client_cert, member_urn, [], {}, session)
        else:
            method = 'lookup_projects_for_member'
            result = self._sa_handler._delegate.lookup_projects_for_member(\
                self._client_cert, member_urn, [], {}, session)
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s" % (method, member_urn))
        chapi_info(PORTAL_LOG_PREFIX, "Result from %s %s" % (method, result))
        return result['value']

    def _get_permissions(self, principal, session):
        chapi_info(PORTAL_LOG_PREFIX, "Invoking get_permissions %s" % \
                      principal)
        result = \
            self._cs_handler._delegate.get_permissions(self._client_cert, 
                                                       principal, [], {}, 
                                                       session)
        chapi_info(PORTAL_LOG_PREFIX, "Result from get_permissions %s: %s" % \
                      (principal, result))
        return result['value']

    # Lookup member_info of a given type
    def _lookup_member_info(self, info_type, match, session):
        options = {'match' : match }
        if info_type == 'public':
            method = 'lookup_public_member_info'
            result = self._ma_handler._delegate.lookup_public_member_info(\
                self._client_cert, [], options, session)
        elif info_type == 'identifying':
            method = 'lookup_identifying_member_info'
            result = self._ma_handler._delegate.lookup_identifying_member_info(\
                self._client_cert, [], options, session)
        elif info_type == 'private':
            method = 'lookup_private_member_info'
            result = self._ma_handler._delegate.lookup_private_member_info(\
                self._client_cert, [], options, session)
        elif info_type == 'public_identifying':
            method = 'lookup_public_identifying_member_info'
            result = \
                self._ma_handler._delegate.lookup_public_identifying_member_info(\
                self._client_cert, [], options, session)
        else:
            raise CHAPIv1ArgumentException("No such member info type %s" % \
                                               info_type)
        
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s" % (method, match))
        chapi_info(PORTAL_LOG_PREFIX, "Result from %s %s" % (method, result))
        return result['value']

    # 
    # Get log entries for given context in last 24 hours
    def _get_log_entries(self, member_uid, project_id, \
                                  slice_id, session):
        if slice_id:
            method = 'get_log_entries_for_context'
            result = self._log_handler._delegate.get_log_entries_for_context(\
                self._client_cert, SLICE_CONTEXT, slice_id, 24, session)
        elif project_id:
            method = 'get_log_entries_for_context'
            result = self._log_handler._delegate.get_log_entries_for_context(\
                self._client_cert, PROJECT_CONTEXT, project_id, 24, session)
                
        else:
            method = 'get_log_entries_by_author'
            result = self._log_handler._delegate.get_log_entries_by_author(\
                self._client_cert, member_uid, 24, session)
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s %s %s" % \
                       (method, member_uid, project_id, slice_id))
        chapi_info(PORTAL_LOG_PREFIX, "Result from %s %s" % (method, result))
        return result['value']

    # Get both requests FOR user and requests BY user (if no slice_id)
    # Register the 'requestor' of the request as someone for whom to gram
    # identifying/public info
    def _get_project_requests(self, member_uid, project_id, slice_id, session):
        if slice_id: return # Nothing to return for specific slice
        context_id = None
        context_type = PROJECT_CONTEXT
        status = PENDING_STATUS
        if project_id:
            context_id = project_id
        method = 'get_requests_by_user'
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s %s %s" % \
                       (method, member_uid, context_type, context_id))
        requests_by_user = \
            self._sa_handler._delegate.get_requests_by_user(\
            self._client_cert, member_uid, context_type, context_id,
            status, [], {}, session)
        self._pending_requests_by_member = requests_by_user['value']
        for request in self._pending_requests_by_member:
            self._record_member_info(request['requestor'], {})
        chapi_info(PORTAL_LOG_PREFIX, "Result %s %s " % \
                       (method, self._pending_requests_by_member))

        method = 'get_requests_for_user'
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s %s %s" % \
                       (method, member_uid, context_type, context_id))
        requests_for_user = \
            self._sa_handler._delegate.get_pending_requests_for_user(\
            self._client_cert, member_uid, context_type, context_id,
            [], {}, session)
        self._pending_requests_for_member = requests_for_user['value']
        for request in self._pending_requests_for_member:
            self._record_member_info(request['requestor'], {})
        chapi_info(PORTAL_LOG_PREFIX, "Result %s %s " % \
                       (method, self._pending_requests_for_member))


    # Pull UID's by key from a list of entries with given UID key field
    def _grab_uids(self, membership_list, uid_field):
        uids = [member_info[uid_field] \
                    for member_info in membership_list \
                    if not member_info['EXPIRED']]
        return uids

    # Register information about a member, adding the attributes to existing
    # set if any so far
    def _record_member_info(self, member_uid, member_info):
        if member_uid not in self._pending_member_uids:
            self._pending_member_uids.append(member_uid)
        current_member_info = {}
        if member_uid in self._member_info_by_uid:
            current_member_info = self._member_info_by_uid[member_uid]
        combined_member_info = \
            dict(current_member_info.items() + member_info.items())
        self._member_info_by_uid[member_uid] = combined_member_info

    # Go through all members that have been referenced in some previous 
    # structure and retrieve all their public and identifying information
    def _resolve_pending_members(self, session):
        method = 'lookup_public_identifying_member_info'
        member_uids = self._pending_member_uids
        chapi_info(PORTAL_LOG_PREFIX, "Invoking %s %s" % (method, member_uids))
        result = self._lookup_member_info('public_identifying', 
                                          {'MEMBER_UID' : member_uids}, 
                                          session)
        for urn, member_data in result.items():
            member_uid = member_data['MEMBER_UID']
            self._record_member_info(member_uid, member_data)
        chapi_info(PORTAL_LOG_PREFIX, "Result from %s %s" % (method, result))


class Portalv1Guard(ABACGuardBase):
    def __init__(self):
        ABACGuardBase.__init__(self)

        # Set of argument checks indexed by method name
    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'portal_query' : 
            SimpleArgumentCheck({'member_eppn' : 'EMAIL',
                                 'project_id' : 'UID_OR_NULL',
                                 'slice_id' : 'UID_OR_NULL'})
        }

    INVOCATION_CHECK_FOR_METHOD = \
        {
        # Only authorities may call portal_query
        'portal_query' : \
            SubjectInvocationCheck([
                "ME.MAY_PORTAL_QUERY<-ME.IS_AUTHORITY"
                ], None, None)
        }


    # Lookup argument check per method (or None if none registered)
    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # Lookup invocation check per method (or None if none registered)
    def get_invocation_check(self, method):
        if self.INVOCATION_CHECK_FOR_METHOD.has_key(method):
            return self.INVOCATION_CHECK_FOR_METHOD[method]
        return None



