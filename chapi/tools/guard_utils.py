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
import json

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

# Return a string based on a URN but with all punctuation (+:-.) 
# replaced with _
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

    q = session.query(db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE, \
                          db.PROJECT_MEMBER_TABLE)
    q = q.filter(db.PROJECT_TABLE.c.expired == 'f')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_TABLE.c.project_id == \
                     db.PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    
    project_names = [row.project_name for row in rows]
    cache[user_urn] = project_names
    return project_names

# Check that a list of UID's are all in the cache, 
# otherwise raise ArgumentException
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
#    chapi_info("ENSURE_VALID_URNS", "%s %s" % (urn_type, urns))
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
            not_found_names = [not_found_urn.split('+')[3] \
                                   for not_found_urn in not_found_urns]
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
    elif urn_type == 'SLIVER_URN':
        q = session.query(db.SLIVER_INFO_TABLE.c.sliver_urn)
        q = q.filter(db.SLIVER_INFO_TABLE.c.sliver_urn.in_(urns))
        rows = q.all()
        found_urns = [row.sliver_urn for row in rows]
        bad_urns = [urn for urn in urns if urn not in found_urns]
        if len(bad_urns) > 0:
            raise CHAPIv1ArgumentError('Unknown sliver urns: [%s]' % bad_urns)
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
        q = session.query(db.SLICE_TABLE.c.slice_urn, \
                              db.SLICE_TABLE.c.slice_id)
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
            raise CHAPIv1ArgumentError("Unknown project uid: %s " % \
                                           project_uid)
    else:
        return validate_uid_list(project_uids, cache, 'project')

# Take a project urn or list of urns, make sure they're all in the cache
# and return a uid or list of uid
def convert_project_urn_to_uid(project_urn, session):
    db = pm.getService('chdbengine')
    config = pm.getService('config')
    authority = config.get("chrm.authority")

    project_urns = project_urn
    if not isinstance(project_urn, list): project_urns = [project_urn]

    if len(project_urns) == 0:
        return []


    cache = cache_get('project_urn_to_uid')
    uncached_urns = [id for id in project_urns if id not in cache]

    if len(uncached_urns) > 0:
        uncached_names = [from_project_urn(urn) for urn in uncached_urns]
        q = session.query(db.PROJECT_TABLE.c.project_name, \
                              db.PROJECT_TABLE.c.project_id)
        q = q.filter(db.PROJECT_TABLE.c.project_name.in_(uncached_names))
        rows = q.all()
        for row in rows:
            project_id = row.project_id
            project_name = row.project_name
            project_urn = to_project_urn(authority, project_name)
            cache[project_urn] = project_id

    if not isinstance(project_urn, list):
        if project_urn in cache:
            return cache[project_urn]
        else:
            raise CHAPIv1ArgumentError("Unknown project urn: %s " % \
                                           project_urn)
    else:
        return validate_uid_list(project_urns, cache, 'project')

# Convert a project URN to project name
def convert_project_urn_to_name(urn, session):
    return from_project_urn(urn)

# Convert a project name to project urn
def convert_project_name_to_urn(name, session):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return to_project_urn(authority, name)

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
    uncached_emails = [em.lower() for em in member_emails \
                           if em.lower() not in cache]

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

# Take an EPPN or list of EPPNs, make sure they're all in the cache
# and return a uid or list of uids
def convert_member_eppn_to_uid(member_eppn, session):
    db = pm.getService('chdbengine')
    member_eppns = member_eppn
    if not isinstance(member_eppn, list): member_eppns = [member_eppn]

    cache = cache_get('member_eppn_to_uid')
    uncached_eppns = [me.lower() for me in member_eppns if me.lower() \
                          not in cache]

    if len(uncached_eppns) > 0:
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(func.lower(db.MEMBER_ATTRIBUTE_TABLE.c.value).in_(uncached_eppns))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'eppn')
        rows = q.all()
        for row in rows:
            eppn_value = row.value.lower()
            member_id = row.member_id
            cache[eppn_value] = member_id

    if not isinstance(member_eppn, list):
        if member_eppn in cache:
            return cache[member_eppn]
        else:
            # Return an empty list if we can't find the eppn.
            return list()
    else:
        return validate_uid_list(member_eppns, cache, 'member_eppn_to_uid')

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
#    chapi_debug('UTILS', 'lookup_operator_privilege: %s = %s' % \
#                    (user_urn, is_operator)
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

# Get role of member on each of list of projects
def get_project_role_for_member(caller_urn, project_urns, session):
    db = pm.getService('chdbengine')
    if not isinstance(project_urns, list): project_urns = [project_urns]
    if len(project_urns) == 0:
#        chapi_debug('UTILS', 
#                    "get_project_role_for_member got " + \
#                        "empty list of project urns")
        return []
    project_names = \
        [get_name_from_urn(project_urn) for project_urn in project_urns]

    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, 
                      db.PROJECT_TABLE.c.project_name, 
                      db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == \
                     db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name.in_(project_names))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()
    return rows

# Get role of member on each of list of slices
def get_slice_role_for_member(caller_urn, slice_urns, session):
    db = pm.getService('chdbengine')
    if not isinstance(slice_urns, list): slice_urns = [slice_urns]
    if len(slice_urns) == 0:
        return []

    q = session.query(db.SLICE_MEMBER_TABLE.c.role, 
                      db.SLICE_TABLE.c.slice_urn, 
                      db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.SLICE_MEMBER_TABLE.c.slice_id == \
                     db.SLICE_TABLE.c.slice_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.SLICE_MEMBER_TABLE.c.member_id)
    q = q.filter(db.SLICE_TABLE.c.slice_urn.in_(slice_urns))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    rows = q.all()
    return rows
        
# Support for parsing CHAPI policies from JSON files
# Take a JSON file and return a dictionary of 
# method => {"policy" : ..., "assertions" :  ... }
def parse_method_policies(filename):
    policies = {}
    try:
        data = open(filename).read()
        raw_policies = json.loads(data)

#        chapi_info("PMP", "DATA = %s" % data)
#        chapi_info("PMP", "RP = %s" % raw_policies)
        
        # Replace names of functions with functions"
        for method_name, method_attrs in raw_policies.items():
            if method_name == "__DOC__" or \
                    isinstance(method_attrs, basestring): 
                continue
#            chapi_info("PMP", "MN = %s MA = %s" % (method_name, method_attrs))
            assertions = None
            extractor = None
            policy_statements = []
            for attr_name, attr_values in method_attrs.items():
#               chapi_info("PMP", "AN = %s AV = %s" % (attr_name, attr_values))
                if attr_name == 'assertions':
                    assertions = attr_values
                elif attr_name == 'policies':
                    raw_policy_statements = attr_values
                    policy_statements = \
                        [rps.replace("$METHOD", method_name.upper()) \
                             for rps in raw_policy_statements]
            policies[method_name] = {"policies" : policy_statements, 
                                     "assertions" : assertions}
    except Exception, e:
        chapi_info("Error", "%s" % e)
        raise Exception("Error parsing policy file: %s" % filename)

    return policies

# The convention of these methods is to return the list of subjects that
# Satisfy the criteria
# e.g. shares_project(member1_urn, member2_urns) returns the 
# subset of member2_urns that share a project with member1_urn

# Return those members of member2_urns that share membership 
# in a project with member1_urn
def shares_project(member1_urn, member2_urns, session, project_uid = None):
    db = pm.getService("chdbengine")
    pm1 = aliased(db.PROJECT_MEMBER_TABLE)
    pm2 = aliased(db.PROJECT_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(pm1.c.project_id, 
                      ma1.c.value.label('member1'), 
                      ma2.c.value.label('member2'))
    if project_uid is not None:
        q = q.filter(pm1.c.project_id == project_uid)
    q = q.filter(pm1.c.project_id == pm2.c.project_id)
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(pm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == member1_urn)
    q = q.filter(ma2.c.value.in_(member2_urns))

    rows = q.all()

    sharers = [row.member2 for row in rows]
    return sharers

# Return those members of member2_urns who share a slice with member1_urn
def shares_slice(member1_urn, member2_urns, session, slice_uid = None):
    db = pm.getService("chdbengine")
    sm1 = aliased(db.SLICE_MEMBER_TABLE)
    sm2 = aliased(db.SLICE_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(sm1.c.slice_id, sm2.c.slice_id, 
                      ma1.c.value.label('member1'), 
                      ma2.c.value.label('member2'))
    if slice_uid is not None:
        q = q.filter(sm1.c.slice_id == slice_uid)
    q = q.filter(sm1.c.slice_id == sm2.c.slice_id)
    q = q.filter(sm1.c.member_id == ma1.c.member_id)
    q = q.filter(sm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == member1_urn)
    q = q.filter(ma2.c.value.in_(member2_urns))

    rows = q.all()

    sharers = [row.member2 for row in rows]
    return sharers

# Return those members of member_urns that have a given role on some object
def has_role_on_some_project(member_urns, role, session):
    db = pm.getService("chdbengine")
    q = session.query(db.PROJECT_MEMBER_TABLE.c.member_id, \
                          db.PROJECT_MEMBER_TABLE.c.role, \
                          db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value.in_(member_urns))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.role == role)

    rows = q.all()

    members_with_role = [row.value for row in rows]
    return members_with_role

# Return the list of members who have a pending request from or 
# to someone in list of other members
# That is, if subject_is_lead
#    Return those members of lead_urns who have a request pending 
#    from one or more of the requestor_urns
# Otherwise if not subject_is_lead
#    Return those members of requestor_urns who have a request pending 
#    to one or more of the lead_urns
def has_pending_request_on_project_lead_by(lead_urns, requestor_urns, 
                                           subject_is_lead, 
                                           session):
    db = pm.getService("chdbengine")
    pm1 = aliased(db.PROJECT_MEMBER_TABLE)
    pm2 = aliased(db.PROJECT_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(db.PROJECT_REQUEST_TABLE.c.status, 
                      ma1.c.value.label('lead_urn'),
                      ma2.c.value.label('requestor_urn'))
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.requestor == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value.in_(lead_urns))
    q = q.filter(ma2.c.value.in_(requestor_urns))
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.context_id == pm1.c.project_id)
    q = q.filter(pm1.c.role.in_([LEAD_ATTRIBUTE, ADMIN_ATTRIBUTE]))
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.status == PENDING_STATUS)

    rows = q.all()

    subjects = requestor_urns
    if subject_is_lead: subjects = lead_urns

    members = []
    for row in rows:
        subject = row.requestor_urn
        if subject_is_lead: subject = row.lead_urn
        members.append(subject)

    return members

# Return the requestor URN of the request ID, or None if none exists
def get_project_request_requestor_urn(request_id, session):
    db = pm.getService("chdbengine")
    q = session.query(db.PROJECT_REQUEST_TABLE.c.requestor, \
                          db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.id == request_id)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.requestor == \
                     db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    rows = q.all()
    if len(rows) > 0:
        requestor_urn = rows[0].value
        return requestor_urn
    else:
        return None

# Return the project URN of the request ID, or None if none exists
def get_project_request_project_urn(request_id, session):
    db = pm.getService("chdbengine")
    q = session.query(db.PROJECT_REQUEST_TABLE.c.context_id)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.id == request_id)
    rows = q.all()
    
    if len(rows) > 0:
        project_uid = rows[0].context_id
        project_urn = convert_project_uid_to_urn(project_uid, session)
        return project_urn
    else:
        return None

# Return the URN of the owner of an SSH key
def get_key_owner_urn(key_id, session):
    db = pm.getService("chdbengine")
    q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == \
                     db.SSH_KEY_TABLE.c.member_id)
    q = q.filter(db.SSH_KEY_TABLE.c.id == key_id)
    rows = q.all()

    owner_urn = None
    if len(rows) > 0:
        owner_urn = rows[0].value
    return owner_urn

