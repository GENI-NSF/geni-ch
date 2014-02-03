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

# A series of utilities for constructing 
#  ABACGuards and SubjectInvocationChecks

import amsoil.core.pluginmanager as pm
from  sqlalchemy import *
from  sqlalchemy.orm import aliased
import threading
from geni_utils import *
from cert_utils import *
from geni_constants import *
from chapi.Memoize import memoize
from chapi.Exceptions import *
import MA_constants as MA
from datetime import datetime, timedelta
from dbutils import add_filters
from chapi_log import *

# context support
_context = threading.local()

# Set up caching of constant relationships of different sorts

# Get the cache of a given name (or create if doesn't exist)
def cache_get(k):
    if not hasattr(_context, 'cache'):
        _context.cache = dict()
    if k not in _context.cache:
        _context.cache[k] = dict()
    return _context.cache[k]

# Remove cache 
def cache_clear():
    if hasattr(_context, 'cache'):
        del _context.cache

# Manage caches that timeout

# Lookup the entry for a given urn (keys: timestamp and value) if not timed out
def timed_cache_lookup(cache, urn, lifetime):
    timeout = datetime.utcnow() - timedelta(seconds=lifetime)
    if urn in cache and cache[urn]['timestamp'] > timeout:
        return cache[urn]
    return None

# Register value with timestamp
def timed_cache_register(cache, urn, value):
    now = datetime.utcnow()
    cache[urn] = {'timestamp' : now, 'value' : value}
    

# Some helper methods

@memoize
# Get the project name from a slice URN
def lookup_project_name_for_slice(slice_urn):
    parts = slice_urn.split("+")
    authority = parts[1]
    authority_parts = authority.split(":")
    project_name = authority_parts[1]
    return project_name

# Return a string based on a URN but with all punctuation (+:-.) replaced with _
def flatten_urn(urn):
    if urn is None or not (isinstance(urn, str) or
                             isinstance(urn, unicode)):
        return str(urn)
    return urn.replace(':', '_').replace('+', '_').replace('-', '_').replace('.', '_')


# Return all names of projects for which a user (by urn) is a member
def lookup_project_names_for_user(user_urn, session):
    db = pm.getService('chdbengine')
    cache = cache_get('project_names_for_user')
    if user_urn in cache:
        return cache[user_urn]

    q = session.query(db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE, db.PROJECT_MEMBER_TABLE)
    q = q.filter(db.PROJECT_TABLE.c.expired == 'f')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    
    project_names = [row.project_name for row in rows]
    cache[user_urn] = project_names
    return project_names

# Check that a list of UID's are all in the cache, otherwise raise ArgumentException
def validate_uid_list(uids, cache, label):
    bad_uids = []
    good_urns = []
    for uid in uids:
        if uid in cache:
            good_urns.append(cache[uid])
        else:
            bad_uids.append(uid)
    if len(bad_uids) > 0:
        raise CHAPIv1ArgumentError("Unknown %s uids [%s] " % (label, bad_uids))
    return good_urns

# Look at a list of URN's of a given type and determine that they are all valid
def ensure_valid_urns(urn_type, urns, session):
    if not isinstance(urns, list): urns = [urns]
    db = pm.getService('chdbengine')
    if urn_type == 'PROJECT_URN':
        authority = pm.getService('config').get("chrm.authority")
        cache = cache_get('project_urns')
        not_found_urns = [urn for urn in urns if urn not in cache]
        if len(not_found_urns) == 0:
#            chapi_debug('UTILS', "No cache misses for project URNs")
            rows = []
        else:
            not_found_names = [not_found_urn.split('+')[3] for not_found_urn in not_found_urns]
            q = session.query(db.PROJECT_TABLE.c.project_name)
            q = q.filter(db.PROJECT_TABLE.c.project_name.in_(not_found_names))
            rows = q.all()
        for row in rows:
            project_name = row.project_name
            project_urn = to_project_urn(authority, project_name)
            cache[project_urn] = True
        bad_urns = [urn for urn in not_found_urns if urn not in cache]
        if len(bad_urns) > 0: 
            raise CHAPIv1ArgumentError('Unknown project urns: [%s]' % bad_urns)
    elif urn_type == 'SLICE_URN':
        cache = cache_get('slice_urns')
        not_found_urns = [urn for urn in urns if urn not in cache]
        if len(not_found_urns) == 0:
#            chapi_debug('UTILS', "No cache misses for slice URNs")
            rows = []
        else:
            q = session.query(db.SLICE_TABLE.c.slice_urn)
            q = q.filter(db.SLICE_TABLE.c.slice_urn.in_(not_found_urns))
            rows = q.all()
        for row in rows:
            cache[row.slice_urn] = True
        bad_urns = [urn for urn in not_found_urns if urn not in cache]
        if len(bad_urns) > 0: 
            raise CHAPIv1ArgumentError('Unknown slice urns: [%s]' % bad_urns)
    elif urn_type == 'MEMBER_URN':
        cache = cache_get('member_urns')
        not_found_urns = [urn for urn in urns if urn not in cache]
        if len(not_found_urns) == 0:
#            chapi_debug('UTILS', "No cache misses for member URNs")
            rows = []
        else:
            q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value)
            q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
            q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value.in_(not_found_urns))
            rows = q.all()
        for row in rows:
            cache[row.value] = True
        bad_urns = [urn for urn in not_found_urns if urn not in cache]
        if len(bad_urns) > 0: 
            raise CHAPIv1ArgumentError('Unknown member urns: [%s]' % bad_urns)
    else:
        pass

# Take a uid or list of uids, make sure they're all in the cache
 # and return a urn or list of urns
def convert_slice_uid_to_urn(slice_uid, session):
    db = pm.getService('chdbengine')
    slice_uids = slice_uid
    if not isinstance(slice_uid, list): slice_uids = [slice_uid]

    if len(slice_uids) == 0:
        return []

    cache = cache_get('slice_uid_to_urn')
    uncached_uids = [id for id in slice_uids if id not in cache]

    if len(uncached_uids) > 0:
        q = session.query(db.SLICE_TABLE.c.slice_urn, db.SLICE_TABLE.c.slice_id)
        q = q.filter(db.SLICE_TABLE.c.slice_id.in_(uncached_uids))
        rows = q.all()
        for row in rows:
            slice_id = row.slice_id
            slice_urn = row.slice_urn
            cache[slice_id] = slice_urn

    if not isinstance(slice_uid, list):
        if slice_uid in cache:
            return cache[slice_uid]
        else:
            raise CHAPIv1ArgumentError('Unknown slice uid: %s' % slice_uid)
    else:
        return validate_uid_list(slice_uids, cache, 'slice')

# Take a uid or list of uids, make sure they're all in the cache
# and return a urn or list of urns
def convert_project_uid_to_urn(project_uid, session):
    db = pm.getService('chdbengine')
    config = pm.getService('config')
    authority = config.get("chrm.authority")

    project_uids = project_uid
    if not isinstance(project_uid, list): project_uids = [project_uid]

    if len(project_uids) == 0:
        return []


    cache = cache_get('project_uid_to_urn')
    uncached_uids = [id for id in project_uids if id not in cache]

    if len(uncached_uids) > 0:
        q = session.query(db.PROJECT_TABLE.c.project_name, \
                              db.PROJECT_TABLE.c.project_id)
        q = q.filter(db.PROJECT_TABLE.c.project_id.in_(uncached_uids))
        rows = q.all()
        for row in rows:
            project_id = row.project_id
            project_name = row.project_name
            project_urn = to_project_urn(authority, project_name)
            cache[project_id] = project_urn

    if not isinstance(project_uid, list):
        if project_uid in cache:
            return cache[project_uid]
        else:
            raise CHAPIv1ArgumentError("Unknown project uid: %s " % project_uid)
    else:
        return validate_uid_list(project_uids, cache, 'project')

# Take a uid or list of uids, make sure they're all in the cache
# and return a urn or list of urns
def convert_member_uid_to_urn(member_uid, session):
    db = pm.getService('chdbengine')
    member_uids = member_uid
    if not isinstance(member_uid, list): member_uids = [member_uid]

    cache = cache_get('member_uid_to_urn')
    uncached_uids = [id for id in member_uids if id not in cache]

    if len(uncached_uids) > 0:
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id.in_(uncached_uids))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        rows = q.all()
        for row in rows:
            member_urn = row.value
            member_id = row.member_id
            cache[member_id] = member_urn
            
    if not isinstance(member_uid, list):
        if member_uid in cache:
            return cache[member_uid]
        else:
            raise CHAPIv1ArgumentError('Unknown member uid: %s ' % member_uid)
    else:
        return validate_uid_list(member_uids, cache, 'member')

# Take a uid or list of uids, make sure they're all in the cache
# and return an email or list of emails
def convert_member_uid_to_email(member_uid, session):
    db = pm.getService('chdbengine')
    member_uids = member_uid
    if not isinstance(member_uid, list): member_uids = [member_uid]

    cache = cache_get('member_uid_to_email')
    uncached_uids = [id for id in member_uids if id not in cache]

    if len(uncached_uids) > 0:
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id.in_(uncached_uids))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'email_address')
        rows = q.all()
        for row in rows:
            member_email = row.value
            member_id = row.member_id
            cache[member_id] = member_email
            
    if not isinstance(member_uid, list):
        if member_uid in cache:
            return cache[member_uid]
        else:
            raise CHAPIv1ArgumentError('Unknown member uid: %s' % member_uid)
    else:
        return validate_uid_list(member_uids, cache, 'member')

# Take an email or list of emails, make sure they're all in the cache
# and return a uid or list of uids
def convert_member_email_to_uid(member_email, session):
    db = pm.getService('chdbengine')
    member_emails = member_email
    if not isinstance(member_email, list): member_emails = [member_email]

    cache = cache_get('member_email_to_uid')
    uncached_emails = [em.lower() for em in member_emails if em.lower() not in cache]

    if len(uncached_emails) > 0:
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(func.lower(db.MEMBER_ATTRIBUTE_TABLE.c.value).in_(uncached_emails))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'email_address')
        rows = q.all()
        for row in rows:
            email_value = row.value.lower()
            member_id = row.member_id
            cache[email_value] = member_id

    # Unlike most other 'convert' routines, we want to return 
    # only the list of good uid's and not error on bad emails
    # To support bulk email or asking about whether an email is valid
    uids = [cache[em.lower()] for em in member_emails if em.lower() in cache]
    return uids

def lookup_slice_urn_for_sliver_urn(sliver_urn, session):
    db = pm.getService('chdbengine')
    
    q = session.query(db.SLIVER_INFO_TABLE.c.slice_urn)
    q = q.filter(db.SLIVER_INFO_TABLE.c.sliver_urn == sliver_urn)
    rows = q.all()
    if len(rows) == 1:
        return rows[0].slice_urn
    else:
        return None
    


# How long do we keep cache entries for operator privileges
OPERATOR_CACHE_LIFETIME_SECS = 60
# How long do we keep cache entries for PI privileges
PI_CACHE_LIFETIME_SECS = 60



# Lookup whether given user (by urn) has 'operator' 
# as an attribute in ma_member_attribute
def lookup_operator_privilege(user_urn, session):
    db = pm.getService('chdbengine')
    cache = cache_get('operator_privilege')
    entry = timed_cache_lookup(cache, user_urn, OPERATOR_CACHE_LIFETIME_SECS)
    if entry:
        return entry['value']

    ma1 = alias(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = alias(db.MEMBER_ATTRIBUTE_TABLE)
    q = session.query(ma2.c.value)
    q = q.filter(ma1.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma1.c.value == user_urn)
    q = q.filter(ma2.c.name == 'OPERATOR')

    rows = q.all()
    is_operator = (len(rows)>0)
#    chapi_debug('UTILS', 'lookup_operator_privilege: '+user_urn+" = "+str(is_operator))
    timed_cache_register(cache, user_urn, is_operator)
    return is_operator

# Is given user an authority?
def lookup_authority_privilege(user_urn, session):
    return user_urn.find("+authority+")>= 0

# Lookup whether given user (by urn) has 'project_lead' 
# as an attribute in ma_member_attribute
def lookup_pi_privilege(user_urn, session):
    db = pm.getService('chdbengine')
    cache = cache_get('pi_privilege')
    entry = timed_cache_lookup(cache, user_urn, PI_CACHE_LIFETIME_SECS)
    if entry:
        return entry['value']

    ma1 = alias(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = alias(db.MEMBER_ATTRIBUTE_TABLE)
    q = session.query(ma2.c.value)
    q = q.filter(ma1.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma1.c.value == user_urn)
    q = q.filter(ma2.c.name == 'PROJECT_LEAD')

#    print "Q = " + str(q)

    rows = q.all()
    is_project_lead = (len(rows)>0)
    timed_cache_register(cache, user_urn, is_project_lead)
    return is_project_lead


# ATTRIBUTE EXTRACTORS:
# Methods to generate assertions based on relationship between the CALLER 
# and the SUBJECT

# If given caller and given subject share a common project
# Generate an ME.SHARES_PROJECT_$subject<-caller assertion
# Three cases:
# 1. find all people who share a project with given caller
#    from among the subjects (member_urns)
# 2. Find all people with a pending join request to project
#     with given subject as lead
# 3. If looking up a member by member_email who is a 
#    project lead or admin, allow it
def assert_shares_project(caller_urn, member_urns, label, options, arguments,
                          abac_manager, session):
#    chapi_info('', "ASP %s %s %s %s" % (caller_urn, member_urns, 
#                                        label, options))
    if label != "MEMBER_URN": return

    # Make sure the list of subjects is a non-empty list
    if isinstance(member_urns, list): 
        # if empty, then we dont share the project.
        if len(member_urns) == 0: return  
    else:
        member_urns = list(member_urns)


    db = pm.getService('chdbengine')
    pm1 = aliased(db.PROJECT_MEMBER_TABLE)
    pm2 = aliased(db.PROJECT_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    # Find all people in the subjects list who share a project
    q = session.query(pm1.c.project_id, pm2.c.project_id, ma1.c.value, ma2.c.value)
    q = q.filter(pm1.c.project_id == pm2.c.project_id)
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(pm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value.in_(member_urns))

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)
    for row in rows:
        member_urn = row[3]  # ma2.c.value
        assertion = "ME.SHARES_PROJECT_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

    # Find all people with a pending join request to project
    # with given subject as lead

    q = session.query(db.PROJECT_REQUEST_TABLE.c.status, ma2.c.value)
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.requestor == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value.in_(member_urns))
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.context_id == pm1.c.project_id)
    q = q.filter(pm1.c.role.in_([LEAD_ATTRIBUTE, ADMIN_ATTRIBUTE]))
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.status == PENDING_STATUS)

    rows = q.all()

    for row in rows:
        member_urn = row[1] # member_urn of project lead on request
        assertion = "ME.HAS_PENDING_REQUEST_ON_SHARED_PROJECT_%s<-CALLER" % \
            flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)


    # If I am looking up a member by member_email,
    # I must be a lead or admin on a project
    if 'match' in options and len(options['match']) == 1 and \
       'MEMBER_EMAIL' in options['match']:
        q = session.query(pm1.c.member_id)
        q = q.filter(pm1.c.member_id == ma1.c.member_id)
        q = q.filter(ma1.c.name == 'urn')
        q = q.filter(ma1.c.value == caller_urn)
        q = q.filter(pm1.c.role.in_([LEAD_ATTRIBUTE, ADMIN_ATTRIBUTE]))
        rows = q.all()
 
        if len(rows) > 0:
            assertion = "ME.IS_LEAD_AND_SEARCHING_EMAIL<-CALLER"
            abac_manager.register_assertion(assertion)

    # If looking up a member by member_uid who is a 
    # lead of an unexpired project, allow it
    if 'match' in options and len(options['match']) == 1 and \
       'MEMBER_UID' in options['match'] and \
       len(options['match']['MEMBER_UID']) > 0:
        member_uids = options['match']['MEMBER_UID']
        q = session.query(ma1.c.value)
        q = q.filter(ma1.c.name == 'urn')
        q = q.filter(ma1.c.member_id == ma2.c.member_id)
        q = q.filter(ma2.c.name == 'PROJECT_LEAD')
        q = q.filter(ma2.c.member_id.in_(member_uids))
        rows = q.all()

        for row in rows:
            member_urn = row.value
            assertion = \
                "ME.IS_LEAD_AND_SEARCHING_UID_%s<-CALLER" % flatten_urn(member_urn)
            abac_manager.register_assertion(assertion)



# If given caller and given subject share a common slice
# Generate an ME.SHARES_SLICE(subject)<-caller assertion
def assert_shares_slice(caller_urn, member_urns, label, options, arguments,
                        abac_manager, session):
    db = pm.getService('chdbengine')
    if not isinstance(member_urns, list): 
        member_urns = list(member_urns)

    if len(member_urns) == 0:
#        chapi_debug('UTILS', "assert_shares_slice got empty list of member URNs")
        return

    if label != "MEMBER_URN": return

    sm1 = aliased(db.SLICE_MEMBER_TABLE)
    sm2 = aliased(db.SLICE_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

#    chapi_debug('UTILS', "assert_shares_slice: %s %s %s %s" % \
#                   (caller_urn, member_urns, label, options))

    q = session.query(sm1.c.slice_id, sm2.c.slice_id, ma1.c.value, ma2.c.value)
    q = q.filter(sm1.c.slice_id == sm2.c.slice_id)
    q = q.filter(sm1.c.member_id == ma1.c.member_id)
    q = q.filter(sm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value.in_(member_urns))

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)

    for row in rows:
        member_urn = row[3] # member_urn of member sharing slice
        assertion = "ME.SHARES_SLICE_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

# Assert ME.IS_$ROLE(SLICE)<-CALLER for all slices of given set 
# of which caller is a member
def assert_slice_role(caller_urn, urns, label, options, arguments, abac_manager, session):
    db = pm.getService('chdbengine')
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    if label == "SLICE_URN":
        rows = get_slice_role_for_member(caller_urn, urns, session)
    elif label == "PROJECT_URN":
        rows = get_project_role_for_member(caller_urn, urns, session)
    else:
        raise CHAPIv1ArgumentError("Call to assert_slice_role with type %s" %\
                                   label)
    for row in rows:
        role = row.role
        if label == "SLICE_URN":
            subject_urn = row.slice_urn
        else:
            project_name = row.project_name
            subject_urn = to_project_urn(authority, project_name)
        role_name = attribute_type_names[role]
        assertion = "ME.IS_%s_%s<-CALLER" % \
                    (role_name, flatten_urn(subject_urn))
#        chapi_debug('UTILS', "assert_slice_role asserting %s" % assertion)
        abac_manager.register_assertion(assertion)

# Get role of member on each of list of projects
def get_project_role_for_member(caller_urn, project_urns, session):
    db = pm.getService('chdbengine')
    if not isinstance(project_urns, list): project_urns = [project_urns]
    if len(project_urns) == 0:
#        chapi_debug('UTILS', "get_project_role_for_member got empty list of project urns")
        return []
    project_names = \
        [get_name_from_urn(project_urn) for project_urn in project_urns]

    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, db.PROJECT_TABLE.c.project_name, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name.in_(project_names))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()
    return rows

def get_slice_role_for_member(caller_urn, slice_urns, session):
    db = pm.getService('chdbengine')
    if not isinstance(slice_urns, list): slice_urns = [slice_urns]
    if len(slice_urns) == 0:
        return []

    q = session.query(db.SLICE_MEMBER_TABLE.c.role, \
                          db.SLICE_TABLE.c.slice_urn, \
                          db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.SLICE_MEMBER_TABLE.c.slice_id == db.SLICE_TABLE.c.slice_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.SLICE_MEMBER_TABLE.c.member_id)
    q = q.filter(db.SLICE_TABLE.c.slice_urn.in_(slice_urns))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    rows = q.all()
    return rows


# Assert ME.IS_$ROLE_$PROJECT<-CALLER for the projects among given set 
# of which caller is a member
def assert_project_role(caller_urn, project_urns, label, options, arguments,
                        abac_manager, session):
    if label != "PROJECT_URN": return
    db = pm.getService('chdbengine')
    rows = get_project_role_for_member(caller_urn, project_urns, session)
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    for row in rows:
        role = row.role
        project_name = row.project_name
        project_urn = to_project_urn(authority, project_name)
        role_name = attribute_type_names[role]
        assertion = "ME.IS_%s_%s<-CALLER" % (role_name, flatten_urn(project_urn))
        abac_manager.register_assertion(assertion)


# Assert ME.BELONGS_TO_$SLICE<-CALLER if caller is member of slice
def assert_belongs_to_slice(caller_urn, slice_urns, label, options, arguments,
                            abac_manager, session):

# ?Needed?    if not isinstance(slice_urns, list): slice_urns = [slice_urns]
    if len(slice_urns) == 0:
        return []

    if label != "SLICE_URN": return

    db = pm.getService('chdbengine')
    q = session.query(db.SLICE_MEMBER_TABLE.c.role, \
                          db.SLICE_TABLE.c.slice_urn, \
                          db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.SLICE_MEMBER_TABLE.c.slice_id == db.SLICE_TABLE.c.slice_id)
    q = q.filter(db.SLICE_TABLE.c.slice_urn.in_(slice_urns))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.SLICE_MEMBER_TABLE.c.member_id)
    rows = q.all()

    for row in rows:
        slice_urn = row.slice_urn
        assertion = "ME.BELONGS_TO_%s<-CALLER" % flatten_urn(slice_urn)
        abac_manager.register_assertion(assertion)


# Assert ME.BELONGS_TO_$PROJECT<-CALLER if caller is member of project
def assert_belongs_to_project(caller_urn, project_urns, label, \
                              options, arguments, abac_manager, session):
    if label != "PROJECT_URN": return
# ?Needed?    if not isinstance(project_urns, list): project_urns = [project_urns]
    project_names = \
        [get_name_from_urn(project_urn) for project_urn in project_urns]
    if len(project_names) == 0:
#        chapi_debug('UTILS', "assert_belongs_to_project got empty list of project names")
        return

    db = pm.getService('chdbengine')
    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, \
                          db.PROJECT_TABLE.c.project_name, \
                          db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == \
                     db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name.in_(project_names))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()

    config = pm.getService('config')
    authority = config.get("chrm.authority")

    for row in rows:
        project_name = row.project_name
        project_urn = to_project_urn(authority, project_name)
        assertion = "ME.BELONGS_TO_%s<-CALLER" % flatten_urn(project_urn)
        abac_manager.register_assertion(assertion)

# Take a request_id and from that determine the context(project) and requestor
# From there, Assert whether the project membership requestor is the caller
# And assert the role on the project of the caller (if any)
def assert_request_id_requestor_and_project_role(caller_urn, request_id, 
                                                 label, options, arguments, abac_manager,
                                                 session):
    request_id = request_id[0] # turn list back into singleton
    if label != "REQUEST_ID" : return
    db = pm.getService('chdbengine')
    q = session.query(db.PROJECT_TABLE.c.project_name, db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.requestor == db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.id == request_id)
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_REQUEST_TABLE.c.context_id)
    rows = q.all()
    if len(rows) > 0:
        project_name = rows[0].project_name
        requestor_urn = rows[0].value
        config = pm.getService('config')
        authority = config.get("chrm.authority")
        project_urn = to_project_urn(authority, project_name)

        if caller_urn == requestor_urn:
            assertion = "ME.IS_REQUESTOR<-CALLER"
            abac_manager.register_assertion(assertion)

        role_rows = get_project_role_for_member(caller_urn, project_urn, session)
        for row in role_rows:
            role = row.role
            role_name = attribute_type_names[role]
            assertion = "ME.IS_%s_%s<-CALLER" % (role_name, request_id)
            abac_manager.register_assertion(assertion)

# Look at the 'attributes' message 
# and determine if the caller is a member of the slice (if present) or project (if present)
def assert_user_belongs_to_slice_or_project(caller_urn, subject_urns, \
                                            label, options, arguments, abac_manager, session):
    # Get the attributes. 
    # If there is one for slice, assert_belongs_to_slice
    # Otherwise, if there is one for project, assert_belogs_to_project
    if 'attributes' not in arguments: return
    attributes = arguments['attributes']
    if 'SLICE' in attributes:
        slice_uid = attributes['SLICE']
        slice_urn = convert_slice_uid_to_urn(slice_uid, session)
        assert_belongs_to_slice(caller_urn, [slice_urn], 'SLICE_URN', options, arguments, 
                                abac_manager, session)
    elif 'PROJECT' in attributes:
        project_uid = attributes['PROJECT']
        project_urn = convert_project_uid_to_urn(project_uid, session)
        assert_belongs_to_project(caller_urn, [project_urn], 'PROJECT_URN', options, arguments, 
                                  abac_manager, session)



# Assert that the caller is invoking the call on self
def assert_user_acting_on_self(caller_urn, subject_urns, \
                                       label, options, arguments, \
                                       abac_manager, session):
    if label == 'MEMBER_URN' and caller_urn in subject_urns:
        assertion = "ME.INVOKING_ON_SELF_%s<-CALLER" % flatten_urn(caller_urn)
        abac_manager.register_assertion(assertion)
        

                                

# Extractors to extract subject identifiers from request
# These return a dictionary of {'SUBJECT_TYPE : [List of SUBJECT IDENTIFIERS OF THIS TYPE]}

# Default subject extractor, only take from the options, ignore arguments
def standard_subject_extractor(options, arguments, session):
    extracted = {}
    if 'match' not in options:
        return None
#        raise CHAPIv1ArgumentError("No match option for query")
    match_option = options['match']
    if "SLICE_URN" in match_option:
        extracted["SLICE_URN"] =  match_option['SLICE_URN']
    if "SLICE_UID" in match_option:
        slice_uids = match_option['SLICE_UID']
        if not isinstance(slice_uids, list): slice_uids = [slice_uids]
        slice_urns = convert_slice_uid_to_urn(slice_uids, session)
        extracted["SLICE_URN"] = slice_urns
    if "PROJECT_URN" in match_option:
        extracted["PROJECT_URN"] =  match_option['PROJECT_URN']
    if "PROJECT_UID" in match_option:
        project_uids = match_option['PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = convert_project_uid_to_urn(project_uids, session)
        extracted["PROJECT_URN"] = project_urns
    if "_GENI_PROJECT_UID" in match_option:
        project_uids = match_option['_GENI_PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = convert_project_uid_to_urn(project_uids, session)
        extracted["PROJECT_URN"] = project_urns
    if "MEMBER_URN" in match_option:
        extracted["MEMBER_URN"] =  match_option['MEMBER_URN']
    if "MEMBER_UID" in match_option:
        member_uids = match_option['MEMBER_UID']
        if not isinstance(member_uids, list): member_uids = [member_uids]
        member_urns = convert_member_uid_to_urn(member_uids, session)
        extracted["MEMBER_URN"] = member_urns
    if '_GENI_KEY_MEMBER_UID' in match_option:
        member_uids = match_option['_GENI_KEY_MEMBER_UID']
        if not isinstance(member_uids, list): member_uids =[member_uids]
        member_urns = convert_member_uid_to_urn(member_uids, session)
        extracted['MEMBER_URN'] = member_urns
    if 'MEMBER_EMAIL' in match_option:
        member_emails = match_option['MEMBER_EMAIL']
        member_uids = convert_member_email_to_uid(member_emails, session)
        member_urns = convert_member_uid_to_urn(member_uids, session)
        extracted['MEMBER_URN'] = member_urns
    return extracted

# For key info methods, extract the subject from options or arguments
def key_subject_extractor(options, arguments, session):
    db = pm.getService('chdbengine')
    extracted = {}
    if 'match' in options:
        match_option = options['match']
    elif 'fields' in options:
        match_option = options['fields']
    elif 'key_id' in arguments:
        match_option = {}
    else:
        raise CHAPIv1ArgumentError("No match/fields option for query")
    if 'KEY_MEMBER' in match_option:
        member_urns = match_option['KEY_MEMBER']
        if not isinstance(member_urns, list): member_urns = [member_urns]
        extracted['MEMBER_URN'] = member_urns
    elif '_GENI_KEY_MEMBER_UID' in match_option:
        member_uids = match_option['_GENI_KEY_MEMBER_UID']
        if not isinstance(member_uids, list): member_uids = [member_uids]
        member_urns = [convert_member_uid_to_urn(member_uid, session) 
                       for member_uid in member_uids]
        extracted['MEMBER_URN'] = member_urns
    elif 'key_id' in arguments:
        key_id = arguments['key_id']
        q = session.query(db.SSH_KEY_TABLE.c.member_id)
        q = q.filter(db.SSH_KEY_TABLE.c.id == key_id)
        rows = q.all()
        if len(rows) != 1:
            raise CHAPIv1ArgumentError("No key with given ID %s" % key_id)
        member_id = rows[0].member_id
        member_urn = convert_member_uid_to_urn(member_id, session)
        extracted['MEMBER_URN'] = member_urn
    else:
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value)
        q = q.filter(db.SSH_KEY_TABLE.c.member_id ==
                     db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name=='urn')
        q = add_filters(q, match_option, db.SSH_KEY_TABLE, MA.key_field_mapping)
        rows = q.all()
        extracted['MEMBER_URN'] = [row.value for row in rows]

    return extracted

# Extract project UID(s) from arguments
def project_uid_extractor(options, arguments, session):
    if 'project_id' in arguments:
        project_id = arguments['project_id']
        project_urn = convert_project_uid_to_urn(project_id, session)
        return {'PROJECT_URN' : project_urn}
    return {}

# Extract project UID from invite_id argument
def project_uid_from_invitation_extractor(options, arguments, session):
    if 'invite_id' in arguments:
        invite_id = arguments['invite_id']
        db = pm.getService('chdbengine')
        q = session.query(db.PROJECT_INVITATION_TABLE)
        q = q.filter(db.PROJECT_INVITATION_TABLE.c.invite_id == invite_id)
        rows = q.all()
        if len(rows) > 0:
            project_id = rows[0].project_id
            return {'PROJECT_UID' : project_id}
    return {}
        
# Extract project URN(s) from options or arguments
def project_urn_extractor(options, arguments, session):
    if 'project_urn' in arguments:
        project_urn = arguments['project_urn']
    elif 'PROJECT_NAME' in options['fields']:
        project_name = options['fields']['PROJECT_NAME']
        config = pm.getService('config')
        authority = config.get('chrm.authority')
        project_urn = to_project_urn(authority, project_name)
    elif 'SLICE_PROJECT_URN' in options['fields']:
        project_urn = options['fields']['SLICE_PROJECT_URN']
    return {"PROJECT_URN" : [project_urn]}

# Extract slice urn from options or arguments
def slice_urn_extractor(options, arguments, session):
    slice_urn = None
    if 'slice_urn' in arguments:
        slice_urn = arguments['slice_urn']
    elif 'fields' in options and 'SLICE_URN' in options['fields']:
        slice_urn = options['fields']['SLICE_URN']
    elif 'fields' in options and 'SLIVER_INFO_SLICE_URN' in options['fields']:
        slice_urn = options['fields']['SLIVER_INFO_SLICE_URN']
    elif 'sliver_urn' in arguments:
        db = pm.getService('chdbengine')
        q = session.query(db.SLIVER_INFO_TABLE.c.slice_urn)
        q = q.filter(db.SLIVER_INFO_TABLE.c.sliver_urn == arguments['sliver_urn'])
        rows = q.all()
        if len(rows) > 0:
            slice_urn = rows[0].slice_urn
    return {"SLICE_URN" : [slice_urn]}

# Extract member urn from options or arguments
def member_urn_extractor(options, arguments, session):
    member_urn = arguments['member_urn']
    return {"MEMBER_URN" : [member_urn]}

# Extract member urn from member_id argument
def member_id_extractor(options, arguments, session):
    member_id = arguments['member_id']
    member_urn = convert_member_uid_to_urn(member_id, session)
    return {"MEMBER_URN" : member_urn}

# Pull project urn out of context_id
def request_context_extractor(options, arguments, session):
    project_uid = arguments['context_id']
    db = pm.getService('chdbengine')
    q = session.query(db.PROJECT_TABLE.c.project_name)
    q = q.filter(db.PROJECT_TABLE.c.project_id == project_uid)
    rows = q.all()
    extracted = {}
    if len(rows) > 0:
        project_name = rows[0].project_name
        config = pm.getService('config')
        authority = config.get("chrm.authority")
        project_urn = to_project_urn(authority, project_name)
        extracted = {"PROJECT_URN" : project_urn}
    return extracted

# Pull request_id out as the subject
def request_id_extractor(options, arguments, session):
    request_id = arguments['request_id']
    extracted = {"REQUEST_ID" : request_id}
    return extracted

# Extract member_id and convert to member_urn
def request_member_extractor(options, arguments, session):
    member_uid = arguments['member_id']
    member_urn = convert_member_uid_to_urn(member_uid, session)
    extracted = {"MEMBER_URN" : member_urn}
    return extracted

# Pull principal out of arguments
def principal_extractor(options, arguments, session):
    principal_uid = arguments['principal']
    principal_urn = convert_member_uid_to_urn(principal_uid, session)
    return {'MEMBER_URN' : principal_urn}


def user_id_extractor(options, arguments, session):
    user_uid = arguments['user_id']
    user_urn = convert_member_uid_to_urn(user_uid, session)
    return {'MEMBER_URN' : user_urn}

def context_extractor(options, arguments, session):
    if 'context_type' in arguments and 'context_id' in arguments:
        context_type = arguments['context_type']
        context_uid = arguments['context_id']
        if context_type == SLICE_CONTEXT:
            slice_uid = context_uid
            slice_urn = convert_slice_uid_to_urn(slice_uid, session)
            return {'SLICE_URN' : slice_urn}
        elif context_type == PROJECT_CONTEXT:
            project_uid = context_uid
            project_urn = convert_project_uid_to_urn(project_uid, session)
            return {'PROJECT_URN' : project_urn}
        elif context_type == MEMBER_CONTEXT:
            member_uid = context_uid
            member_urn = convert_member_uid_to_urn(member_uid, session)
            return {'MEMBER_URN' : member_urn}
    else:
        return {}
        
def attribute_extractor(options, arguments, session):
    if 'attributes' not in arguments: return
    attributes = arguments['attributes']
    if 'SLICE' in attributes:
        slice_uid = attributes['SLICE']
        slice_urn = convert_slice_uid_to_urn(slice_uid, session)
        return {'SLICE_URN' : slice_urn}
    if 'PROJECT' in attributes:
        project_uid = attributes['PROJECT']
        project_urn = convert_project_uid_to_urn(project_uid, session)
        return {'PROEJCT_URN' : project_urn}
    if "MEMBER" in attributes:
        member_uid = attributes['MEMBER']
        member_urn = convert_member_uid_to_urn(member_uid, session)
        return {'MEMBER_URN' : member_urn}

# Support for lookup_sliver_info guards

def sliver_info_extractor(options, arguments, session):
    if 'match' in options:
        match = options['match']
        if 'SLIVER_INFO_CREATOR_URN' in match:
            return {'MEMBER_URN' : match['SLIVER_INFO_CREATOR_URN']}
        elif 'SLIVER_INFO_SLICE_URN' in match:
            return {'SLICE_URN' : match['SLIVER_INFO_SLICE_URN']}
        elif 'SLIVER_INFO_URN' in match:
            sliver_urns = match['SLIVER_INFO_URN']
            if not isinstance(sliver_urns, list): sliver_urns = [sliver_urns]
            chapi_info("SIE", "SLIVER_URNS = %s" % sliver_urns)
            slice_urns = [lookup_slice_urn_for_sliver_urn(sliver_urn, session)
                          for sliver_urn in sliver_urns]
            chapi_info("SIE", "SLICE_URNS = %s" % slice_urns)
            return {'SLICE_URN' : slice_urns}
    raise CHAPIv1ArgumentError("Illegal options for lookup_sliver_info: %s"%\
                                   options)
        
