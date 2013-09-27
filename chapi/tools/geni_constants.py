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

# Sets of constants for defining relationships and roles in GENI 
# Registry and Authorities

# Context Types
PROJECT_CONTEXT = 1
SLICE_CONTEXT = 2
RESOURCE_CONTEXT = 3
SERVICE_CONTEXT = 4
MEMBER_CONTEXT = 5

# For translating context types to names (if stored that way in database)
context_type_names = {PROJECT_CONTEXT : "PROJECT", SLICE_CONTEXT : "SLICE", 
                      RESOURCE_CONTEXT : "RESOURCE", SERVICE_CONTEXT : "SERVICE",
                      MEMBER_CONTEXT : "MEMBER"}

# Attribute (role) Types
LEAD_ATTRIBUTE = 1
ADMIN_ATTRIBUTE = 2
MEMBER_ATTRIBUTE = 3
AUDITOR_ATTRIBUTE = 4
OPERATOR_ATTRIBUTE = 5

attribute_type_names = { LEAD_ATTRIBUTE : "LEAD", ADMIN_ATTRIBUTE : "ADMIN", 
                         MEMBER_ATTRIBUTE : "MEMBER", AUDITOR_ATTRIBUTE : "AUDITOR",
                         OPERATOR_ATTRIBUTE : "OPERATOR"}

# Request status codes from rq_constants.php
PENDING_STATUS = 0

# Datetime format for parsing/creating dates
DATETIME_FORMAT_1 = "%Y-%m-%d %H:%M:%S"
DATETIME_FORMAT_2 = "%m/%d/%Y %H:%M:%S"
DATETIME_FORMAT_3 = "%m/%d/%Y"
