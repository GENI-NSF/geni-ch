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

# Utility functions for morphing from native schema to public-facing
# schema

import tools.pluginmanager as pm
from datetime import datetime
from cert_utils import *

# Turn a project URN into a project name
def from_project_urn(project_urn):
    parts = project_urn.split('+')
    return parts[len(parts)-1]

# Turn a project name into a project URN
def to_project_urn(authority, project_name):
    return "urn:publicid:IDN+%s+project+%s" % \
        (authority, project_name)

# Turn a row with project name into a project URN
def row_to_project_urn(authority, row):
    return to_project_urn(authority, row.project_name)

def urn_for_slice(slice_name, project_name):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return "urn:publicid:IDN+%s:%s+slice+%s" % \
        (authority, project_name, slice_name)

# Pull the URL of the server from the environment
def get_server_url():
    from plugins.chapiv1rpc.chapi.MethodContext import invocation_context
    if 'SCRIPT_URI' in invocation_context.environ:
        return invocation_context.environ['SCRIPT_URI']
    else:
        return "https://%s%s" % (invocation_context.environ['HTTP_HOST'], 
                                  invocation_context.environ['REQUEST_URI'])
    
# Return the user display name
# First, try '_GENI_MEMBER_DISPLAYNAME'
# Then try 'MEMBER_FIRSTNAME' 'MEMBER_LASTNAME'
# Then try 'MEMBER_EMAIL'
# Then pull the username from the urn
def get_member_display_name(member_identifying_info, member_urn):
    if "_GENI_MEMBER_DISPLAYNAME" in member_identifying_info and member_identifying_info['_GENI_MEMBER_DISPLAYNAME']:
        return member_identifying_info['_GENI_MEMBER_DISPLAYNAME']
    elif "MEMBER_FIRSTNAME" in member_identifying_info and "MEMBER_LASTNAME" in member_identifying_info \
            and member_identifying_info['MEMBER_FIRSTNAME'] and member_identifying_info['MEMBER_LASTNAME']:
        return "%s %s" % (member_identifying_info['MEMBER_FIRSTNAME'], member_identifying_info['MEMBER_LASTNAME'])
    elif "MEMBER_EMAIL" in member_identifying_info and member_identifying_info['MEMBER_EMAIL']:
        return member_identifying_info['MEMBER_EMAIL']
    else:
        return get_name_from_urn(member_urn)

