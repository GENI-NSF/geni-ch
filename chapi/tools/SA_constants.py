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

from tools.geni_utils import row_to_project_urn

services = ["SLICE", "PROJECT", "SLICE_MEMBER", "PROJECT_MEMBER", "SLIVER_INFO"]

credential_types = [
    {"type" : "geni_sfa", "version" : 3},
    {"type" : "geni_abac", "version" : 1}
    ]

SLICE_CERT_LIFETIME = 365*10 # days
SLICE_MAX_RENEWAL_DAYS = 185
SLICE_DEFAULT_LIFE_DAYS = 7 # See create_slice
# FIXME: Slice name regex, length

# The externally visible data schema for slices
slice_mandatory_fields  = {
    "SLICE_URN": {"TYPE": "URN"},
    "SLICE_UID": {"TYPE": "UID"},
    "SLICE_NAME": {"TYPE": "STRING", "CREATE": "REQUIRED"},
    "SLICE_DESCRIPTION": {"TYPE": "STRING", "CREATE": "ALLOWED",
                          "UPDATE": True},
    "SLICE_EXPIRATION": {"TYPE": "DATETIME", "CREATE" : "ALLOWED",
                         "UPDATE": True},
    "SLICE_EXPIRED": {"TYPE": "BOOLEAN"},
    "SLICE_CREATION": {"TYPE": "DATETIME"},
    "SLICE_PROJECT_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False}
}

slice_supplemental_fields = {
    "_GENI_SLICE_OWNER" : {"OBJECT": "SLICE", "TYPE" : "UID", "UPDATE" : True},
    "_GENI_SLICE_EMAIL": {"OBJECT": "SLICE", "TYPE": "EMAIL",
                          "CREATE": "ALLOWED", "UPDATE": True},
    "_GENI_PROJECT_UID": {"OBJECT": "SLICE", "TYPE" : "UID", "UPDATE" : False}
}

# The externally visible data schema for slivers
sliver_info_mandatory_fields  = {
    "SLIVER_INFO_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False},
    "SLIVER_INFO_SLICE_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False},
    "SLIVER_INFO_AGGREGATE_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False},
    "SLIVER_INFO_CREATOR_URN": {"TYPE": "URN", "CREATE": "REQUIRED", "UPDATE": False},
    "SLIVER_INFO_EXPIRATION": {"TYPE": "DATETIME", "CREATE" : "ALLOWED", "UPDATE": True},
    "SLIVER_INFO_CREATION": {"TYPE": "DATETIME", "CREATE" : "ALLOWED", "UPDATE": False},
}

sliver_info_supplemental_fields = {
}

# The externally visible data schema for projects
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
    "_GENI_PROJECT_OWNER" : {"OBJECT": "PROJECT", "TYPE" : "UID",
                             "CREATE" : "ALLOWED", "UPDATE" : True},
    "_GENI_PROJECT_EMAIL": {"OBJECT": "PROJECT", "TYPE": "EMAIL",
                            "CREATE": "ALLOWED", "UPDATE": True}
}

# Total set of supplemental fields
supplemental_fields = dict(slice_supplemental_fields.items() + \
                           project_supplemental_fields.items() + \
                           sliver_info_supplemental_fields.items())

# Mapping from external to internal data schema (SLICE)
slice_field_mapping = {
    "SLICE_URN" : "slice_urn",
    "SLICE_UID" : "slice_id",
    "SLICE_NAME" : "slice_name",
    "SLICE_DESCRIPTION" :  "slice_description",
    "SLICE_EXPIRATION" :  "expiration",
    "SLICE_EXPIRED" :  "expired",
    "SLICE_CREATION" :  "creation",
    "SLICE_PROJECT_URN" : row_to_project_urn,
    "_GENI_SLICE_EMAIL" : "slice_email",
    "_GENI_SLICE_OWNER" : "owner_id", 
    "_GENI_PROJECT_UID": 'project_id'
}

# Mapping from external to internal data schema (SLIVER_INFO)
sliver_info_field_mapping = {
    "SLIVER_INFO_URN" : "sliver_urn",
    "SLIVER_INFO_SLICE_URN" : "slice_urn",
    "SLIVER_INFO_CREATOR_URN" : "creator_urn",
    "SLIVER_INFO_AGGREGATE_URN" : "aggregate_urn",
    "SLIVER_INFO_EXPIRATION" :  "expiration",
    "SLIVER_INFO_CREATION" :  "creation",
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
    "_GENI_PROJECT_EMAIL" : "project_email",
    "_GENI_PROJECT_OWNER" : "lead_id"
}

project_request_columns = [
    'id', 'context_type', 'context_id', 'request_text', 'request_type',
    'request_details', 'requestor', 'status', 'creation_timestamp',
    'resolver', 'resolution_timestamp', 'resolution_description'
]

PROJECT_DEFAULT_INVITATION_EXPIRATION_HOURS = 72
# FIXME: project name length, regex

project_request_field_mapping = {
    'id' : 'id', 
    'context_type' : 'context_type', 
    'context_id' : 'context_id', 
    'request_text' : 'request_text', 
    'request_type' : 'request_type', 
    'request_details' : 'request_details', 
    'requestor' : 'requestor', 
    'status' : 'status', 
    'creation_timestamp' : 'creation_timestamp', 
    'resolver'  : 'resolver' , 
    'resolution_timestamp' : 'resolution_timestamp', 
    'resolution_description' : 'resolution_description'
}
