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

credential_types = [
    {"type" : "geni_sfa", "version" : "3"},
    {"type" : "geni_abac", "version" : "1"}
    ]

standard_fields = {
    "MEMBER_URN" : {"TYPE" : "URN", "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "MEMBER_UID": {"TYPE" : "UID", "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "MEMBER_FIRSTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
    "MEMBER_LASTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
    "MEMBER_USERNAME" : {"TYPE" : "STRING", "PROTECT" : "PUBLIC"},
    "MEMBER_EMAIL" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"}
}

optional_fields = {
    "_GENI_MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", \
               "OBJECT": "MEMBER", "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_PHONE_NUMBER": {"TYPE": "STRING", "CREATE": "ALLOWED", \
               "OBJECT": "MEMBER", "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", \
              "OBJECT": "MEMBER", "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_EPPN": {"TYPE": "STRING", "CREATE": "ALLOWED", \
       "OBJECT": "MEMBER", "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_SSL_CERTIFICATE": {"OBJECT": "MEMBER", \
                  "TYPE": "CERTIFICATE"},
    "_GENI_MEMBER_SSL_EXPIRATION": {"OBJECT": "MEMBER",
                                    "TYPE": "DATETIME"},
    "_GENI_MEMBER_SSL_PRIVATE_KEY": {"OBJECT": "MEMBER", "TYPE": "KEY", "PROTECT": "PRIVATE"},
    "_GENI_MEMBER_INSIDE_CERTIFICATE": {"OBJECT": "MEMBER", "TYPE": "CERTIFICATE"},
    "_GENI_MEMBER_INSIDE_PRIVATE_KEY": {"OBJECT": "MEMBER", "TYPE": "KEY", "PROTECT": "PRIVATE"},
    "_GENI_IDENTIFYING_MEMBER_UID": {"OBJECT": "MEMBER", "TYPE" : "UID", \
          "UPDATE" : False, "PROTECT" : "IDENTIFYING"},
    "_GENI_PRIVATE_MEMBER_UID": {"OBJECT": "MEMBER", "TYPE" : "UID", \
          "UPDATE" : False, "PROTECT" : "PRIVATE"},
    "_GENI_ENABLE_WIMAX" : {"OBJECT" : "MEMBER", "TYPE" : "UID", \
                                "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "_GENI_ENABLE_WIMAX_BUTTON" : {"OBJECT" : "MEMBER", "TYPE" : "BOOLEAN", \
                                       "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "_GENI_ENABLE_IRODS" : {"OBJECT" : "MEMBER", "TYPE" : "BOOLEAN", \
                                "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "_GENI_IRODS_USERNAME" : {"OBJECT" : "MEMBER", "TYPE" : "STRING", \
                                "UPDATE" : False, "PROTECT" : "IDENTIFYING"},
    "_GENI_WIMAX_USERNAME" : {"OBJECT" : "MEMBER", "TYPE" : "STRING", \
                                "UPDATE" : False, "PROTECT" : "IDENTIFYING"},
    "_GENI_MEMBER_ENABLED" : {"OBJECT" : "MEMBER", "TYPE" : "BOOLEAN",
                              "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "_GENI_MEMBER_URL" : {"OBJECT" : "MEMBER", "TYPE" : "STRING",
                              "UPDATE" : True, "PROTECT" : "IDENTIFYING"},
    "_GENI_MEMBER_REASON" : {"OBJECT" : "MEMBER", "TYPE" : "STRING",
                              "UPDATE" : True, "PROTECT" : "IDENTIFYING"},
    "_GENI_MEMBER_REFERENCE" : {"OBJECT" : "MEMBER", "TYPE" : "STRING",
                              "UPDATE" : True, "PROTECT" : "IDENTIFYING"}
}

standard_plus_optional = dict(standard_fields.items() + optional_fields.items())

standard_key_fields = { 
    "KEY_MEMBER" : {"TYPE" : "URN", "CREATE" : "REQUIRED"}, \
    "KEY_ID" : {"TYPE" : "STRING"}, \
    "KEY_TYPE" : {"TYPE" : "STRING", "CREATE" : "ALLOWED"}, \
    "KEY_PUBLIC" : {"TYPE" : "KEY", "CREATE" : "REQUIRED"},  \
    "KEY_PRIVATE" : {"TYPE" : "KEY", "CREATE" : "ALLOWED"}, \
    "KEY_DESCRIPTION" : \
         {"TYPE" : "STRING", "CREATE" : "ALLOWED", "UPDATE" : True} 
}

optional_key_fields = {
    "_GENI_KEY_FILENAME" : {"OBJECT" : "KEY", "TYPE" : "STRING", \
            "UPDATE" : True, "CREATE" : "ALLOWED"},
    "_GENI_KEY_MEMBER_UID" : {"OBJECT" : "KEY", "TYPE" : "UID"}
}

# Mapping from external to internal data schema
field_mapping = {
    "MEMBER_URN": "urn",
    "MEMBER_UID": "member_id",
    "MEMBER_FIRSTNAME": "first_name",
    "MEMBER_LASTNAME": "last_name",
    "MEMBER_USERNAME": "username",
    "MEMBER_EMAIL": "email_address",
    "_GENI_MEMBER_DISPLAYNAME": "displayName",
    "_GENI_MEMBER_PHONE_NUMBER": "telephone_number",
    "_GENI_MEMBER_AFFILIATION": "affiliation",
    "_GENI_MEMBER_EPPN": "eppn",
    "_GENI_MEMBER_SSL_CERTIFICATE": "certificate",
    "_GENI_MEMBER_SSL_PRIVATE_KEY": "private_key",
    "_GENI_MEMBER_SSL_EXPIRATION": "expiration",
    "_GENI_MEMBER_INSIDE_CERTIFICATE": "certificate",
    "_GENI_MEMBER_INSIDE_PRIVATE_KEY": "private_key",
    "_GENI_IDENTIFYING_MEMBER_UID": "member_id",
    "_GENI_PRIVATE_MEMBER_UID": "member_id",
    "_GENI_ENABLE_WIMAX" : "enable_wimax",
    "_GENI_ENABLE_WIMAX_BUTTON" : "enable_wimax_button",
    "_GENI_ENABLE_IRODS" : "enable_irods",
    "_GENI_IRODS_USERNAME" : "irods_username",
    "_GENI_WIMAX_USERNAME" : "wimax_username",
    "_GENI_MEMBER_ENABLED" : "member_enabled",
    "_GENI_MEMBER_URL": "url",
    "_GENI_MEMBER_REASON": "reason",
    "_GENI_MEMBER_REFERENCE": "reference",

    # these are special - used in the database but not fields specifiable in the API
    "PROJECT_LEAD": "PROJECT_LEAD",
    "OPERATOR": "OPERATOR"
}

key_fields = ["KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", "KEY_TYPE",
              "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", 
              "_GENI_KEY_FILENAME" ]

key_field_mapping = {
    "KEY_MEMBER": 'value',
    "KEY_ID": 'id',
    "KEY_PUBLIC": "public_key",
    "KEY_PRIVATE": "private_key",
    "KEY_TYPE" : "key_type",
    "KEY_DESCRIPTION":  "description",
    "_GENI_KEY_MEMBER_UID": "member_id",
    "_GENI_KEY_FILENAME": "filename"
}

objects = ["MEMBER", "KEY"]
services = ["MEMBER", "KEY"]

attributes = [
    "MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", "MEMBER_LASTNAME",
    "MEMBER_USERNAME", "MEMBER_EMAIL", "_GENI_MEMBER_DISPLAYNAME",
    "_GENI_MEMBER_PHONE_NUMBER", "_GENI_MEMBER_AFFILIATION",
    "_GENI_MEMBER_EPPN", "KEY_MEMBER", "KEY_ID", 
    "KEY_PUBLIC", "KEY_PRIVATE", "KEY_TYPE",
    "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", "_GENI_KEY_FILENAME",
    "_GENI_MEMBER_ENABLED", "_GENI_ENABLE_WIMAX", "_GENI_ENABLE_WIMAX_BUTTON", 
    "_GENI_ENABLE_IRODS", "_GENI_IRODS_USERNAME", "_GENI_WIMAX_USERNAME",
    "_GENI_MEMBER_URL", "_GENI_MEMBER_REASON", "_GENI_MEMBER_REFERENCE"
]

public_fields = [
    "MEMBER_URN", "MEMBER_UID", "MEMBER_USERNAME",
    "_GENI_MEMBER_SSL_CERTIFICATE",
    "_GENI_MEMBER_SSL_EXPIRATION",
    "_GENI_MEMBER_INSIDE_CERTIFICATE", "_GENI_MEMBER_ENABLED",
    "_GENI_ENABLE_WIMAX", "_GENI_ENABLE_WIMAX_BUTTON", "_GENI_ENABLE_IRODS"
]

identifying_fields = [
    "MEMBER_FIRSTNAME", "MEMBER_LASTNAME", "MEMBER_EMAIL",
    "_GENI_MEMBER_DISPLAYNAME", "_GENI_MEMBER_PHONE_NUMBER",
    "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN",
    "_GENI_IDENTIFYING_MEMBER_UID",
    "_GENI_IRODS_USERNAME", "_GENI_WIMAX_USERNAME",
    "_GENI_MEMBER_URL", "_GENI_MEMBER_REASON", "_GENI_MEMBER_REFERENCE"
]

private_fields = [
    "_GENI_MEMBER_SSL_PRIVATE_KEY", "_GENI_MEMBER_INSIDE_PRIVATE_KEY",
    "_GENI_PRIVATE_MEMBER_UID",

]

match_fields = [
    "MEMBER_URN", "MEMBER_UID", "MEMBER_FIRSTNAME", "MEMBER_LASTNAME",
    "MEMBER_USERNAME", "MEMBER_EMAIL", "_GENI_MEMBER_EPPN", "_GENI_ENABLE_WIMAX"
]

required_create_key_fields = ["KEY_PUBLIC", "KEY_MEMBER"]
allowed_create_key_fields = [
    "KEY_PUBLIC", "KEY_PRIVATE", "KEY_DESCRIPTION",
    "_GENI_KEY_FILENAME", "KEY_MEMBER"
]
updatable_key_fields = ["KEY_DESCRIPTION", "_GENI_KEY_FILENAME"]

USER_CRED_LIFE_YEARS = 1 # See MA.get_user_credential
# FIXME: username regex

