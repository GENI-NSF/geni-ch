#----------------------------------------------------------------------
# Copyright (c) 2011-2015 Raytheon BBN Technologies
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

# Constants for the CH (Federation Registry service)
# AKA Service Registry (SR) AKA  Clearinghouse (CH)

# List of services provided by the CH server
services = ["SERVICE"]

# dictionary of types of services provided by the CH (name : code)
# That is the kinds of services that are advertised in the CH
SERVICE_AGGREGATE_MANAGER = 0
SERVICE_SLICE_AUTHORITY = 1
SERVICE_PROJECT_AUTHORITY = 2
SERVICE_MEMBER_AUTHORITY = 3
SERVICE_AUTHORIZATION_SERVICE = 4
SERVICE_LOGGING_SERVICE = 5
SERVICE_CREDENTIAL_STORE = 6
SERVICE_CERTIFICATE_AUTHORITY = 7
SERVICE_KEY_MANAGER = 8
SERVICE_PGCH = 9
SERVICE_WIMAX_SITE = 10
SERVICE_IRODS = 11

service_types = {
    "AGGREGATE_MANAGER" : SERVICE_AGGREGATE_MANAGER,
    "SLICE_AUTHORITY" : SERVICE_SLICE_AUTHORITY,
    "PROJECT_AUTHORITY" : SERVICE_PROJECT_AUTHORITY,
    "MEMBER_AUTHORITY" : SERVICE_MEMBER_AUTHORITY,
    "AUTHORIZATION_SERVICE" : SERVICE_AUTHORIZATION_SERVICE,
    "LOGGING_SERVICE" : SERVICE_LOGGING_SERVICE,
    "CREDENTIAL_STORE" : SERVICE_CREDENTIAL_STORE,
    "CERTIFICATE_AUTHORITY" : SERVICE_CERTIFICATE_AUTHORITY,
    "KEY_MANAGER" : SERVICE_KEY_MANAGER,
    "PGCH" : SERVICE_PGCH,
    "WIMAX_SITE" : SERVICE_WIMAX_SITE,
    "IRODS" : SERVICE_IRODS
}

# Mapping from external to internal data schema
field_mapping = {
    "_GENI_SERVICE_ID" : "id",
    "SERVICE_URN": 'service_urn',
    "SERVICE_URL": 'service_url',
    "_GENI_SERVICE_CERT_FILENAME": 'service_cert',
    "SERVICE_CERT": 'service_cert',
    "SERVICE_NAME": 'service_name',
    "SERVICE_DESCRIPTION": 'service_description',
    "SERVICE_TYPE": "service_type",
    "_GENI_SERVICE_SHORT_NAME": "short_name"
    }

# The externally visible data schema for services
mandatory_fields = { 
    "SERVICE_URN": {"TYPE": "URN"},
    "SERVICE_URL": {"TYPE": "URL"},
    "SERVICE_CERT": {"TYPE": "CERTIFICATE"},
    "SERVICE_NAME" : {"TYPE" : "STRING"},
    "SERVICE_DESCRIPTION": {"TYPE" : "STRING"}
    }

supplemental_fields = { 
    "_GENI_SERVICE_CERT_FILENAME": {"TYPE": "STRING", "OBJECT": "SERVICE"},
    "_GENI_SERVICE_ID" : {"TYPE" : "INTEGER", "OBJECT": "SERVICE"},
    "_GENI_SERVICE_ATTRIBUTES" : {"TYPE" : "DICTIONARY", "OBJECT" : "SERVICE"},
    "_GENI_SERVICE_SHORT_NAME" : {"TYPE": "STRING", "OBJECT": "SERVICE"}
    }


# Defined attributes on services
# A dictionary: For each attribute we have a name pointing to a dictionary
# with 'description', 'service_types', 'acceptable_values'
# 'service_types' means a list of service types to which this attribute
# applies. This tag is optional and if not supplied it is not restricted
# 'acceptable_values' means a list of acceptable values for this attribute
# This tag is optional and if not supplied it is not restricted
defined_attributes = {
    "SPEAKS_FOR" : {
        "description" : "Does this aggregate accept speaks-for credentials and options?",
        "service_types" : [SERVICE_AGGREGATE_MANAGER],
        "acceptable_values" : ['t', 'f']
        },
    "AM_API_VERSION" : {
        "description" : "The version of the AM API supported by this aggregate",
        "service_types" : [SERVICE_AGGREGATE_MANAGER],
        "acceptable_values" : ['1', '2', '3']
        }
}


