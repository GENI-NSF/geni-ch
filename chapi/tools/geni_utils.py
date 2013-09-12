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

# Utility functions for morphing from native schema to public-facing
# schema

import amsoil.core.pluginmanager as pm

# Turn a project URN into a project name
def from_project_urn(project_urn):
    parts = project_urn.split('+')
    return parts[len(parts)-1]

# Turn a project name into a project URN
def to_project_urn(authority, project_name):
    return "urn:publicid:IDN+%s+project+%s" % \
        (authority, project_name)

# Turn a row with project name into a project URN
def row_to_project_urn(row):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return to_project_urn(authority, row.project_name)

def urn_for_slice(slice_name, project_name):
    config = pm.getService('config')
    authority = config.get("chrm.authority")
    return "urn:publicid:IDN+%s:%s+slice+%s" % \
        (authority, project_name, slice_name)

