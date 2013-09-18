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

# context support
_context = threading.local()

def cache_get(k):
    if not hasattr(_context, 'cache'):
        _context.cache = dict()
    if k not in _context.cache:
        _context.cache[k] = dict()
    return _context.cache[k]

def cache_clear():
    if hasattr(_context, 'cache'):
        del _context.cache

# Some helper methods

@memoize
def extract_user_urn(client_cert):
    client_cert_object = \
        sfa.trust.certificate.Certificate(string=client_cert)
    user_urn = None
    identifiers = client_cert_object.get_extension('subjectAltName')
    identifier_parts = identifiers.split(',')
    for identifier in identifier_parts:
        identifier = identifier.strip()
        if identifier.startswith('URI:urn:publicid'):
            user_urn = identifier[4:]
            break
    return user_urn

@memoize
def lookup_project_name_for_slice(slice_urn):
    parts = slice_urn.split("+")
    authority = parts[1]
    authority_parts = authority.split(":")
    project_name = authority_parts[1]
    return project_name

# Return a string based on a URN but with all punctuation (+:-.) replaced with _
def flatten_urn(urn):
    return urn.replace(':', '_').replace('+', '_').replace('-', '_').replace('.', '_')

def lookup_project_names_for_user(user_urn):
    cache = cache_get('project_names_for_user')
    if user_urn in cache:
        return cache[user_urn]

    db = pm.getService('chdbengine')
    session = db.getSession()

    q = session.query(db.PROJECT_TABLE, db.MEMBER_ATTRIBUTE_TABLE, db.PROJECT_MEMBER_TABLE)
    q = q.filter(db.PROJECT_TABLE.c.expired == 'f')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_MEMBER_TABLE.c.project_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)
    rows = q.all()
    session.close()
    
    project_names = [row.project_name for row in rows]
    cache[user_urn] = project_names
    return project_names

# Take a uid or list of uids, make sure they're all in the cache
# and return a urn or list of urns
def convert_slice_uid_to_urn(slice_uid):
    slice_uids = slice_uid
    if not isinstance(slice_uid, list): slice_uids = [slice_uid]

    cache = cache_get('slice_uid_to_urn')
    uncached_uids = [id for id in slice_uids if id not in cache]

    if len(uncached_uids) > 0:
        db = pm.getService('chdbengine')
        session = db.getSession()
        q = session.query(db.SLICE_TABLE.c.slice_urn, db.SLICE_TABLE.c.slice_id)
        q = q.filter(db.SLICE_TABLE.c.slice_id.in_(uncached_uids))
        rows = q.all()
        session.close()
        for row in rows:
            slice_id = row.slice_id
            slice_urn = row.slice_urn
            cache[slice_id] = slice_urn

    if not isinstance(slice_uid, list):
        if slice_uid in cache:
            return cache[slice_uid]
        else:
            return None
    else:
        return [cache[id] for id in slice_uids if id in cache]

# Take a uid or list of uids, make sure they're all in the cache
# and return a urn or list of urns
def convert_project_uid_to_urn(project_uid):

    config = pm.getService('config')
    authority = config.get("chrm.authority")

    project_uids = project_uid
    if not isinstance(project_uid, list): project_uids = [project_uid]

    cache = cache_get('project_uid_to_urn')
    uncached_uids = [id for id in project_uids if id not in cache]

    if len(uncached_uids) > 0:
        db = pm.getService('chdbengine')
        session = db.getSession()
        q = session.query(db.PROJECT_TABLE.c.project_name, \
                              db.PROJECT_TABLE.c.project_id)
        q = q.filter(db.PROJECT_TABLE.c.project_id.in_(uncached_uids))
        rows = q.all()
        session.close()
        for row in rows:
            project_id = row.project_id
            project_name = row.project_name
            project_urn = to_project_urn(authority, project_name)
            cache[project_id] = project_urn

    if not isinstance(project_uid, list):
        if project_uid in cache:
            return cache[project_uid]
        else:
            return None
    else:
        return [cache[id] for id in project_uids if id in cache]


# Take a uid or list of uids, make sure they're all in the cache
# and return a urn or list of urns
def convert_member_uid_to_urn(member_uid):

    member_uids = member_uid
    if not isinstance(member_uid, list): member_uids = [member_uid]

    cache = cache_get('member_uid_to_urn')
    uncached_uids = [id for id in member_uids if id not in cache]

    if len(uncached_uids) > 0:
        db = pm.getService('chdbengine')
        session = db.getSession()
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id.in_(uncached_uids))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
        rows = q.all()
        session.close()
        for row in rows:
            member_urn = row.value
            member_id = row.member_id
            cache[member_id] = member_urn
            
    if not isinstance(member_uid, list):
        if member_uid in cache:
            return cache[member_uid]
        else:
            return None
    else:
        return [cache[id] for id in member_uids if id in cache]

# Take a uid or list of uids, make sure they're all in the cache
# and return an email or list of emails
def convert_member_uid_to_email(member_uid):

    member_uids = member_uid
    if not isinstance(member_uid, list): member_uids = [member_uid]

    cache = cache_get('member_uid_to_email')
    uncached_uids = [id for id in member_uids if id not in cache]

    if len(uncached_uids) > 0:
        db = pm.getService('chdbengine')
        session = db.getSession()
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id.in_(uncached_uids))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'email_address')
        rows = q.all()
        session.close()
        for row in rows:
            member_email = row.value
            member_id = row.member_id
            cache[member_id] = member_email
            
    if not isinstance(member_uid, list):
        if member_uid in cache:
            return cache[member_uid]
        else:
            return None
    else:
        return [cache[id] for id in member_uids if id in cache]


# Take an email or list of emails, make sure they're all in the cache
# and return a uid or list of uids
def convert_member_email_to_uid(member_email):

    member_emails = member_email
    if not isinstance(member_email, list): member_emails = [member_email]

    cache = cache_get('member_email_to_uid')
    uncached_emails = [em for em in member_emails if em not in cache]

    if len(uncached_emails) > 0:
        db = pm.getService('chdbengine')
        session = db.getSession()
        q = session.query(db.MEMBER_ATTRIBUTE_TABLE.c.value, \
                              db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value.in_(uncached_emails))
        q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'email_address')
        rows = q.all()
        session.close()
        for row in rows:
            member_email = row.value
            member_id = row.member_id
            cache[member_email] = member_id
            
    if not isinstance(member_email, list):
        if member_email in cache:
            return cache[member_email]
        else:
            return None
    else:
        return [cache[em] for em in member_emails if em in cache]

def lookup_operator_privilege(user_urn):
    cache = cache_get('operator_privilege')
    if user_urn in cache:
        return cache[user_urn]
    db = pm.getService('chdbengine')
    session = db.getSession()

    OPERATOR_ATTRIBUTE = 5
    SLICE_CONTEXT = 2

    q = session.query(db.CS_ASSERTION_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.context_type == SLICE_CONTEXT)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.CS_ASSERTION_TABLE.c.principal)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    session.close()
    cache[user_urn] = (len(rows)>0)
    return len(rows) > 0

def lookup_authority_privilege(user_urn):
    return user_urn.find("+authority+")>= 0

def lookup_pi_privilege(user_urn):
    cache = cache_get('pi_privilege')
    if user_urn in cache:
        return cache[user_urn]
    db = pm.getService('chdbengine')
    session = db.getSession()

    OPERATOR_ATTRIBUTE = 5
    RESOURCE_CONTEXT = 3

    q = session.query(db.CS_ASSERTION_TABLE, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.attribute == OPERATOR_ATTRIBUTE)
    q = q.filter(db.CS_ASSERTION_TABLE.c.context_type == RESOURCE_CONTEXT)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.CS_ASSERTION_TABLE.c.principal)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == user_urn)

    rows = q.all()
    session.close()
    cache[user_urn] = (len(rows)>0)
    return len(rows) > 0

# ATTRIBUTE EXTRACTORS:
# Methods to generate assertions based on relationship between the CALLER 
# and the SUBJECT

# If given caller and given subject share a common project
# Generate an ME.SHARES_PROJECT_$subject<-caller assertion
def assert_shares_project(caller_urn, member_urns, label, abac_manager):
    if isinstance(member_urns, list): 
        member_urn = member_urns[0] # Pull singleton URN from list
    else:
        member_urn = member_urns
    if label != "MEMBER_URN": return
    db = pm.getService('chdbengine')
    session = db.getSession()

    pm1 = aliased(db.PROJECT_MEMBER_TABLE)
    pm2 = aliased(db.PROJECT_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(pm1.c.project_id, pm2.c.project_id, ma1.c.value, ma2.c.value)
    q = q.filter(pm1.c.project_id == pm2.c.project_id)
    q = q.filter(pm1.c.member_id == ma1.c.member_id)
    q = q.filter(pm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value == member_urn)

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)
    session.close()
    if len(rows) > 0:
        assertion = "ME.SHARES_PROJECT_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

# If given caller and given subject share a common slice
# Generate an ME.SHARES_SLICE(subject)<-caller assertion
def assert_shares_slice(caller_urn, member_urns, label, abac_manager):
    if isinstance(member_urns, list): 
        member_urn = member_urns[0] # Pull singleton URN from list
    else:
        member_urn = member_urns
    if label != "MEMBER_URN": return
    db = pm.getService('chdbengine')
    session = db.getSession()

    sm1 = aliased(db.SLICE_MEMBER_TABLE)
    sm2 = aliased(db.SLICE_MEMBER_TABLE)
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)

    q = session.query(sm1.c.slice_id, sm2.c.slice_id, ma1.c.value, ma2.c.value)
    q = q.filter(sm1.c.slice_id == sm2.c.slice_id)
    q = q.filter(sm1.c.member_id == ma1.c.member_id)
    q = q.filter(sm2.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma2.c.name == 'urn')
    q = q.filter(ma1.c.value == caller_urn)
    q = q.filter(ma2.c.value == member_urn)

    rows = q.all()
#    print "ROWS = " + str(len(rows)) + " " + str(rows)
    session.close()

    if len(rows) > 0:
        assertion = "ME.SHARES_SLICE_%s<-CALLER" % flatten_urn(member_urn)
        abac_manager.register_assertion(assertion)

# Assert ME.IS_$ROLE(SLICE)<-CALLER for all slices of given set 
# of which caller is a member
def assert_slice_role(caller_urn, slice_urns, label, abac_manager):
    db = pm.getService('chdbengine')
    session = db.getSession()
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
    session.close()

    for row in rows:
        role = row.role
        slice_urn = row.slice_urn
        role_name = attribute_type_names[role]
        assertion = "ME.IS_%s_%s<-CALLER" % (role_name, flatten_urn(slice_urn))
        abac_manager.register_assertion(assertion)

def get_project_role_for_member(caller_urn, project_urns):
    db = pm.getService('chdbengine')
    session = db.getSession()
    if not isinstance(project_urns, list): project_urns = [project_urns]
    project_names = \
        [get_name_from_urn(project_urn) for project_urn in project_urns]

    q = session.query(db.PROJECT_MEMBER_TABLE.c.role, db.PROJECT_TABLE.c.project_name, db.MEMBER_ATTRIBUTE_TABLE)
    q = q.filter(db.PROJECT_MEMBER_TABLE.c.project_id == db.PROJECT_TABLE.c.project_id)
    q = q.filter(db.PROJECT_TABLE.c.project_name.in_(project_names))
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.value == caller_urn)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.member_id == db.PROJECT_MEMBER_TABLE.c.member_id)
    rows = q.all()
    session.close()
    return rows


# Assert ME.IS_$ROLE_$PROJECT<-CALLER for the projects among given set 
# of which caller is a member
def assert_project_role(caller_urn, project_urns, label, abac_manager):
    if label != "PROJECT_URN": return
    rows = get_project_role_for_member(caller_urn, project_urns)
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
def assert_belongs_to_slice(caller_urn, slice_urns, label, abac_manager):
    if label != "SLICE_URN": return
    db = pm.getService('chdbengine')
    session = db.getSession()

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
    session.close()

    for row in rows:
        slice_urn = row.slice_urn
        assertion = "ME.BELONGS_TO_%s<-CALLER" % flatten_urn(slice_urn)
        abac_manager.register_assertion(assertion)


# Assert ME.BELONGS_TO_$PROJECT<-CALLER if caller is member of project
def assert_belongs_to_project(caller_urn, project_urns, label, abac_manager):
    if label != "PROJECT_URN": return
    db = pm.getService('chdbengine')
    session = db.getSession()
    project_names = \
        [get_name_from_urn(project_urn) for project_urn in project_urns]

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
    session.close()

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
def assert_request_id_requestor_and_project_role(caller_urn, request_id, label, abac_manager):
    request_id = request_id[0] # turn list back into singleton
    if label != "REQUEST_ID" : return
    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(db.PROJECT_TABLE.c.project_name, db.MEMBER_ATTRIBUTE_TABLE.c.value)
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.requestor == db.MEMBER_ATTRIBUTE_TABLE.c.member_id)
    q = q.filter(db.MEMBER_ATTRIBUTE_TABLE.c.name == 'urn')
    q = q.filter(db.PROJECT_REQUEST_TABLE.c.id == request_id)
    q = q.filter(db.PROJECT_TABLE.c.project_id == db.PROJECT_REQUEST_TABLE.c.context_id)
    rows = q.all()
    session.close()
    if len(rows) > 0:
        project_name = rows[0].project_name
        requestor_urn = rows[0].value
        config = pm.getService('config')
        authority = config.get("chrm.authority")
        project_urn = to_project_urn(authority, project_name)

        if caller_urn == requestor_urn:
            assertion = "ME.IS_REQUESTOR<-CALLER"
            abac_manager.register_assertion(assertion)

        role_rows = get_project_role_for_member(caller_urn, project_urn)
        for row in role_rows:
            role = row.role
            role_name = attribute_type_names[role]
            assertion = "ME.IS_%s_%s<-CALLER" % (role_name, request_id)
            abac_manager.register_assertion(assertion)

# Extractors to extract subject identifiers from request
# These return a dictionary of {'SUBJECT_TYPE : [List of SUBJECT IDENTIFIERS OF THIS TYPE]}

# Default subject extractor, only take from the options, ignore arguments
def standard_subject_extractor(options, arguments):
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
        slice_urns = convert_slice_uid_to_urn(slice_uids)
        extracted["SLICE_URN"] = slice_urns
    if "PROJECT_URN" in match_option:
        extracted["PROJECT_URN"] =  match_option['PROJECT_URN']
    if "PROJECT_UID" in match_option:
        project_uids = match_option['PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = convert_project_uid_to_urn(project_uids)
        extracted["PROJECT_URN"] = project_urns
    if "_GENI_PROJECT_UID" in match_option:
        project_uids = match_option['_GENI_PROJECT_UID']
        if not isinstance(project_uids, list): project_uids = [project_uids]
        project_urns = convert_project_uid_to_urn(project_uids)
        extracted["PROJECT_URN"] = project_urns
    if "MEMBER_URN" in match_option:
        extracted["MEMBER_URN"] =  match_option['MEMBER_URN']
    if "MEMBER_UID" in match_option:
        member_uids = match_option['MEMBER_UID']
        if not isinstance(member_uids, list): member_uids = [member_uids]
        member_urns = convert_member_uid_to_urn(member_uids)
        extracted["MEMBER_URN"] = member_urns
    if '_GENI_KEY_MEMBER_UID' in match_option:
        member_uids = match_option['_GENI_KEY_MEMBER_UID']
        if not isinstance(member_uids, list): member_uids =[member_uids]
        member_urns = convert_member_uid_to_urn(member_uids)
        extracted['MEMBER_URN'] = member_urns
    if 'MEMBER_EMAIL' in match_option:
        member_emails = match_option['MEMBER_EMAIL']
        member_uids = convert_member_email_to_uid(member_emails)
        member_urns = convert_member_uid_to_urn(member_uids)
        extracted['MEMBER_URN'] = member_urns
    return extracted

def key_subject_extractor(options, arguments):
    extracted = {}
    if 'match' not in options:
        raise CHAPIv1ArgumentError("No match option for query")
    match_option = options['match']
    if 'KEY_MEMBER' in match_option:
        member_urns = match_option['KEY_MEMBER']
        if not isinstance(member_urns, list): member_urns = [member_urns]
        extracted['MEMBER_URN'] = member_urns
    if '_GENI_KEY_MEMBER_UID' in match_option:
        member_uids = match_option['_GENI_KEY_MEMBER_UID']
        if not isinstance(member_uids, list): member_uids = [member_uids]
        member_urns = [convert_member_uid_to_urn(member_uid) for member_uid in member_uids]
        extracted['MEMBER_URN'] = member_urns
    return extracted
        

def project_urn_extractor(options, arguments):
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

def slice_urn_extractor(options, arguments):
    slice_urn = arguments['slice_urn']
    return {"SLICE_URN" : [slice_urn]}

def member_urn_extractor(options, arguments):
    member_urn = arguments['member_urn']
    return {"MEMBER_URN" : [member_urn]}

# Pull project urn out of context_id
def request_context_extractor(options, arguments):
    project_uid = arguments['context_id']
    db = pm.getService('chdbengine')
    session = db.getSession()
    q = session.query(db.PROJECT_TABLE.c.project_name)
    q = q.filter(db.PROJECT_TABLE.c.project_id == project_uid)
    rows = q.all()
    session.close()
    extracted = {}
    if len(rows) > 0:
        project_name = rows[0].project_name
        config = pm.getService('config')
        authority = config.get("chrm.authority")
        project_urn = to_project_urn(authority, project_name)
        extracted = {"PROJECT_URN" : project_urn}
    return extracted


# Pull project_id out as the subject
def request_id_context_extractor(options, arguments):
    request_id = arguments['request_id']
    extracted = {"REQUEST_ID" : request_id}
    return extracted

def request_member_extractor(options, arguments):
    member_uid = arguments['member_id']
    member_urn = convert_member_uid_to_urn(member_uid)
    extracted = {"MEMBER_URN" : member_urn}
    return extracted

# Pull principal out of arguments
def principal_extractor(options, arguments):
    principal_uid = arguments['principal']
    principal_urn = convert_member_uid_to_urn(principal_uid)
    return {'MEMBER_URN' : principal_urn}




