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

credential_types = ["SFA", "ABAC"]

standard_fields = {
    "MEMBER_URN" : {"TYPE" : " URN", "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "MEMBER_UID": {"TYPE" : "UID", "UPDATE" : False, "PROTECT" : "PUBLIC"},
    "MEMBER_FIRSTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
    "MEMBER_LASTNAME" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"},
    "MEMBER_USERNAME" : {"TYPE" : "STRING", "PROTECT" : "PUBLIC"},
    "MEMBER_EMAIL" : {"TYPE" : "STRING", "PROTECT" : "IDENTIFYING"}
}

optional_fields = {
    "_GENI_MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                                "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_PHONE_NUMBER": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                                "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                               "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_EPPN": {"TYPE": "STRING", "CREATE": "ALLOWED", \
                        "UPDATE": True, "PROTECT": "IDENTIFYING"},
    "_GENI_MEMBER_SSL_PUBLIC_KEY": {"TYPE": "KEY"},
    "_GENI_MEMBER_SSL_CERTIFICATE": {"TYPE": "CERTIFICATE"},
    "_GENI_MEMBER_SSL_PRIVATE_KEY": {"TYPE": "KEY", "PROTECT": "PRIVATE"},
    "_GENI_MEMBER_INSIDE_PUBLIC_KEY": {"TYPE": "KEY"},
    "_GENI_MEMBER_INSIDE_CERTIFICATE": {"TYPE": "CERTIFICATE"},
    "_GENI_MEMBER_INSIDE_PRIVATE_KEY": {"TYPE": "KEY", "PROTECT": "PRIVATE"},
    "_GENI_USER_CREDENTIAL": {"TYPE": "CREDENTIALS"},
    "_GENI_CREDENTIALS": {"TYPE": "CREDENTIALS"},
    # TODO: perhaps allow _GENI_MEMBER_ENABLED?
}

standard_key_fields = { 
    "KEY_MEMBER" : {"TYPE" : "URN", "CREATE" : "REQUIRED"}, \
    "KEY_ID" : {"TYPE" : "UID"}, \
    "KEY_PUBLIC" : {"TYPE" : "KEY", "CREATE" : "REQUIRED"},  \
    "KEY_PRIVATE" : {"TYPE" : "KEY", "CREATE" : "ALLOWED"}, \
    "KEY_DESCRIPTION" : \
         {"TYPE" : "STRING", "CREATE" : "ALLOWED", "UPDATE" : True} 
}

optional_key_fields = {
    "_GENI_KEY_FILENAME" : \
        {"TYPE" : "STRING", "UPDATE" : True, "CREATE" : "ALLOWED"}
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
    "_GENI_MEMBER_SSL_PUBLIC_KEY": None,
    "_GENI_MEMBER_SSL_PRIVATE_KEY": "private_key",
    "_GENI_MEMBER_INSIDE_PUBLIC_KEY": None,
    "_GENI_MEMBER_INSIDE_CERTIFICATE": "certificate",
    "_GENI_MEMBER_INSIDE_PRIVATE_KEY": "private_key",
    "_GENI_USER_CREDENTIAL": "foo",
    "_GENI_CREDENTIALS": "foo",
}

key_fields = ["KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", 
              "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", 
              "_GENI_KEY_FILENAME" ]

key_field_mapping = {
    "KEY_MEMBER": 'value',
    "KEY_ID": 'id',
    "KEY_PUBLIC": "public_key",
    "KEY_PRIVATE": "private_key",
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
    "_GENI_MEMBER_EPPN", "KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE",
    "KEY_DESCRIPTION", "_GENI_KEY_MEMBER_UID", "_GENI_KEY_FILENAME",
    "_GENI_MEMBER_ENABLED"
]

# TODO: _GENI_MEMBER_ENABLED is special - can it be searched?

public_fields = [
    "MEMBER_URN", "MEMBER_UID", "MEMBER_USERNAME",
    "_GENI_MEMBER_SSL_PUBLIC_KEY", "_GENI_MEMBER_SSL_CERTIFICATE",
    "_GENI_MEMBER_INSIDE_PUBLIC_KEY", "_GENI_MEMBER_INSIDE_CERTIFICATE",
    "_GENI_USER_CREDENTIAL", "_GENI_CREDENTIALS"
]

identifying_fields = [
    "MEMBER_FIRSTNAME", "MEMBER_LASTNAME", "MEMBER_USERNAME", "MEMBER_EMAIL",
    "MEMBER_URN", "MEMBER_UID", "_GENI_MEMBER_DISPLAYNAME",
    "_GENI_MEMBER_PHONE_NUMBER", "_GENI_MEMBER_AFFILIATION", "_GENI_MEMBER_EPPN"
]

private_fields = [
    "_GENI_MEMBER_SSL_PRIVATE_KEY", "MEMBER_URN", "MEMBER_UID",
    "_GENI_MEMBER_INSIDE_PRIVATE_KEY"
]

key_fields = [
    "KEY_MEMBER", "KEY_ID", "KEY_PUBLIC", "KEY_PRIVATE", "KEY_DESCRIPTION",
    "_GENI_KEY_MEMBER_UID", "_GENI_KEY_FILENAME"
]

required_create_key_fields = ["KEY_PUBLIC"]
allowed_create_key_fields = [
    "KEY_PUBLIC", "KEY_PRIVATE", "KEY_DESCRIPTION", "_GENI_KEY_FILENAME"
]
updatable_key_fields = ["KEY_DESCRIPTION", "_GENI_KEY_FILENAME"]
