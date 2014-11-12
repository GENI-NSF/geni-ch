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

from chapi_log import *
from chapi.Exceptions import *
import types
from datetime import *
from  sqlalchemy.orm import aliased

# A set of utilities for dealing with SQL alchemy as the database backend
# Convert between external (in get_version) and internal (in database) field names
# Support query and filter clauses

# Convert external field name to internal field name based on given mapping
def convert_to_internal(external_field, mapping):
    if not mapping.has_key(external_field):
        raise CHAPIv1ArgumentError("No such field in schema : " + external_field)
    return mapping[external_field]

# Convert the keys name/value dictionary  from external to internal
def convert_dict_to_internal(external_dict, mapping):
    internal_dict = {}
    for external_key in external_dict.keys():
        value = external_dict[external_key]
        internal_key = convert_to_internal(external_key, mapping)
        internal_dict[internal_key] = value
    return internal_dict

# Make sure all required fields are in dictionary keys
# And only allowwable fields are in dictionary keys
def validate_fields(fields_dict, required_keys, allowed_keys):
    # Are all required keys in fields_dict key
    missing_required_keys = []
    if required_keys:
        for required_key in required_keys:
            if not required_key in fields_dict:
                missing_required_keys.append(required_key)

    if len(missing_required_keys) > 0:
        raise CHAPIv1ArgumentError("Missing required key" +  \
                                       "for DB transaction : %s" \
                                       % missing_required_keys)

    # Are all field_dict_keys allowed?
    unallowed_keys = []
    for key in fields_dict.keys():
        if not key in allowed_keys:
            unallowed_keys.append(key)

    if len(unallowed_keys) > 0:
        raise CHAPIv1ArgumentError("Unallowed keys for DB transaction : %s" \
                                       % unallowed_keys)


# Convert internal field name to external field name based on given mapping
def convert_to_external(internal_field, mapping):
    external_field = None
    for external_key in mapping.keys():
        internal_field_name = mapping[external_key]
        if internal_field_name == internal_field:
            external_field = external_key
            break
    if not external_field:
        raise CHAPIv1ArgumentError("No such field in schema : " + internal_field)
    return external_field


# Add filter clauses to a query based on given match criteria
# Return updated query
def add_filters(query, match_criteria, table, mapping, session):
    if match_criteria:
        for external_match_field in match_criteria.keys():
            internal_match_field = convert_to_internal(external_match_field, mapping)
            match_value = match_criteria[external_match_field]
            if isinstance(internal_match_field, types.DictionaryType):
                base_field = internal_match_field['base_field']
                column = table.c[base_field]
                to_internal = internal_match_field['to_internal']
                if isinstance(match_value, types.ListType):
                    match_value = \
                        [to_internal(mv, session) for mv in match_value]
                else:
                    match_value = to_internal(match_value, session)
            else:
                column = table.c[internal_match_field]
            if isinstance(match_value, types.ListType):
                if len(match_value) > 0:
                    query = query.filter(column.in_(match_value))
                else:
                    query = query.filter(column == None)
            else:
                query = query.filter(column == match_value)
    return query

STANDARD_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Construct a result row {external_field : value, external_field : value} 
# from row which is a set of values indexed by internal fields
def construct_result_row(row, columns, mapping, session):
    result_row = {}
    for column in columns:
        internal_name = convert_to_internal(column, mapping)
#        print "IN = " + str(internal_name) + " " + str(type(internal_name))
        if isinstance(internal_name, types.DictionaryType):
            base_field = internal_name['base_field']
            internal_value = eval("row.%s" % base_field)
            to_external = internal_name['to_external']
            column_value = to_external(internal_value, session)
        elif isinstance(internal_name, types.FunctionType):
            column_value = internal_name(row)
        else:
            column_value = eval("row.%s" % internal_name)
        if isinstance(column_value, datetime):
            column_value = column_value.strftime(STANDARD_DATETIME_FORMAT)
        result_row[column] = column_value
    return result_row

def unpack_query_options(options, mapping):
    """Unpack the query options and return a tuple of
    selected columns (a list) and match criteria (a dict).
    """
    # Default selected columns is all
    selected_columns = mapping.keys()
    if options.has_key('filter'):
        selected_columns = options['filter']

    # Default match criteria is none (empty dict)
    match_criteria = {}
    if options.has_key('match'):
        match_criteria = options['match']

    return selected_columns, match_criteria

# Split the set of member urns into enabled and disabled member urns
def check_disabled_users(db, member_urns, session):
    if member_urns is None or (isinstance(member_urns, types.ListType) and len(member_urns) == 0):
        return [], []
    ma1 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    ma2 = aliased(db.MEMBER_ATTRIBUTE_TABLE)
    q = session.query(ma1.c.value)
    q = q.filter(ma1.c.member_id == ma2.c.member_id)
    q = q.filter(ma1.c.name == 'urn')
    q = q.filter(ma1.c.value.in_(member_urns))
    q = q.filter(ma2.c.name == 'member_enabled')
    q = q.filter(ma2.c.value == 'n')
    rows = q.all()
    disabled_members = [row.value for row in rows]
    enabled_members = [member_urn for member_urn in member_urns \
                           if member_urn not in disabled_members]
    return enabled_members, disabled_members
       


