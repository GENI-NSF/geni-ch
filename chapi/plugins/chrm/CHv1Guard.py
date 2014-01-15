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

from ABACGuard import *
from ArgumentCheck import *
from CHv1Implementation import CHv1Implementation

# Specific guard for GPO CH
# These are all open calls (no authN or authZ) , so all we do is argument
# checking

# A 'match' criteria is optional for ghe CH get_* methods
class CHGetServicesCheck(FieldsArgumentCheck):
    def __init__(self, mandatory_fields, supplemental_fields):
        FieldsArgumentCheck.__init__(self, None, None, \
                                         mandatory_fields, supplemental_fields)

    def validate(self, options, arguments):
        FieldsArgumentCheck.validate(self, options, arguments)

        if 'match' in options:
            self.validateFieldValueDictionary(options['match'])

        if 'filter' in options:
            self.validateFieldList(options['filter'])

class CHv1Guard(ABACGuardBase):

    ARGUMENT_CHECK_FOR_METHOD = \
        {
        'lookup_member_authorities' : \
            CHGetServicesCheck(CHv1Implementation.mandatory_fields, \
                                   CHv1Implementation.supplemental_fields),
        'lookup_slice_authorities' : \
            CHGetServicesCheck(CHv1Implementation.mandatory_fields, \
                                   CHv1Implementation.supplemental_fields),
        'lookup_aggregates' : \
            CHGetServicesCheck(CHv1Implementation.mandatory_fields, \
                                   CHv1Implementation.supplemental_fields),
        'lookup_aggregates_for_urns' :
            ValidURNCheck('urns')
        }

    def get_argument_check(self, method):
        if self.ARGUMENT_CHECK_FOR_METHOD.has_key(method):
            return self.ARGUMENT_CHECK_FOR_METHOD[method]
        return None

    # The CH methods are all openly available: no invocation or row checks
    def get_invocation_check(self, method):
        return None

    def get_row_check(self, method):
        return None

