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

from chapi.Exceptions import *
from geni.util.urn_util import is_valid_urn
from tools.geni_constants import *
from sfa.trust.certificate import Certificate
import types
import uuid
from datetime import datetime


# Create a subset 'fields' dictionary with only fields in given list
def select_fields(field_definitions, field_list):
    subset = {}
    for key in field_definitions.keys():
        if key in field_list:
            subset[key] = field_definitions[key]
    return subset


# Base class for checking validity of call arguments
class ArgumentCheck:
    def validate(self, options, arguments):
        raise CHAPIv1NotImplementedError('Base Class: ArgumentCheck.validate')


# Argument check based on sets of mandatory and supplemental fields
# defined for a given object schema, indicating which are required
# or permitted fields for a given operation
class FieldsArgumentCheck(ArgumentCheck):

    # Args:
    # field_option - The name of the option key contianing field information
    #   to verify against the object schema
    # additional_required_options - Additional required options keys
    # mandatory_fields: Any CH/MA/SA must implement these fields in their
    #   object model
    # supplemental_fields: This particular CH/MA/SA implements these 
    #   addtional fields
    # argument_types: dictionary of additional arguments (not in options) and their required types
    def __init__(self, field_option, additional_required_options, \
                     mandatory_fields, supplemental_fields, argument_types=None):
        self._field_option = field_option
        self._additional_required_options = additional_required_options
        self._mandatory_fields = mandatory_fields
        self._supplemental_fields = supplemental_fields
        self._argument_types = argument_types

    def validate(self, options, arguments):

        if self._field_option and self._field_option not in options.keys():
            raise CHAPIv1ArgumentError("Missing Option: " \
                                           + str(self._field_option))
            
        # Check to see that all the additional required options are present
        if self._additional_required_options:
            for required_option in self._additional_required_options:
                if not required_option in options:
                    raise CHAPIv1ArgumentError("Missing Option: " \
                                                   + required_option)

        # Check all the typed arguments
        self.validateArgumentFormats(arguments)

    # Make sure all object fields provided are recognized 
    def validateFieldList(self, fields):
        for field in fields:
            if not field in self._mandatory_fields and \
                    not  field in self._supplemental_fields:
                raise CHAPIv1ArgumentError("Unrecognized field : " + field)

                           
    # Take a list of {field : value} dictionaries
    # Make sure all field name/value pairs are recognized and of proper type
    def validateFieldValueDictionary(self, field_values):

        for field in field_values.keys():
            value = field_values[field]
            if not field in self._mandatory_fields and \
                    not field in self._supplemental_fields:
                raise CHAPIv1ArgumentError("Unrecognized field : " + field)
            self.validateFieldValueFormat(field, value)

    # Validate that a given field has proper format by looking up type
    def validateFieldValueFormat(self, field, value):
        field_type = None
        if field in self._mandatory_fields and 'TYPE' in self._mandatory_fields[field]:
            field_type = self._mandatory_fields[field]['TYPE']
        if not field_type:
            if field in self._supplemental_fields and 'TYPE' in self._supplemental_fields[field]:
                field_type = self._supplemental_fields[field]['TYPE']
        if not field_type:
            raise CHAPIv1ArgumentError("No type defined for field: %s" % field)
        self.validateTypedField(field, field_type, value)

    # Validate format arguments (not options)
    def validateArgumentFormats(self, arguments):
        if arguments is not None and len(arguments) > 0 and self._argument_types == None:
            raise CHAPIv1ArgumentError("No argument types provided for arguments : %s" % arguments)
        for arg_name, arg_value in arguments.items():
            if not arg_name in self._argument_types:
                raise CHAPIv1ArgumentError("No argument type provided for argument %s" % arg_name)
            arg_type = self._argument_types[arg_name]
            self.validateTypedField(arg_name, arg_type, arg_value)

    # Validate that a given field value of given type has proper format 
    def validateTypedField(self, field, field_type, value):

        properly_formed = True
        if field_type == "URN":
            if isinstance(value, list):
                for v in value:
                    if not is_valid_urn(v):
                        properly_formed = False
                        break
            else:
                properly_formed = is_valid_urn(value)
        elif field_type == "UID":
            try:
                if isinstance(value, list):
                    for v in value: uuid.UUID(v)
                else:
                    uuid.UUID(value)
            except Exception as e:
                properly_formed = False
        elif field_type == "STRING":
            pass # Always true
        elif field_type == "INTEGER":
            try:
                int(value)
            except Exception as e:
                properly_formed = False
        elif field_type == "DATETIME":
            try:
                datetime.strptime(value, DATETIME_FORMAT_1)
            except Exception as e:
                try:
                    datetime.strptime(value, DATETIME_FORMAT_2)
                except Exception as e:
                    try:
                        datetime.strptime(value, DATETIME_FORMAT_3)
                    except Exception as e:
                        if value: properly_formed = False
        elif field_type == "EMAIL":
            properly_formed = value.find('@')>= 0 and value.find('.') >= 0
        elif field_type == "KEY":
            pass # *** No standard format
        elif field_type == "BOOLEAN":
            properly_formed = value.lower() in ['t', 'f', 'true', 'false']
        elif field_type == "CREDENTIALS":
            try:
                Credential(string=value)
            except Exception as e:
                properly_formed = False
        elif field_type == "CERTIFICATE":
            try:
                cert = Certificate()
                cert.load_from_string(value)
            except Exception as e:
                properly_formed = False
        else:
            raise CHAPIv1ArgumentError("Unsupported field type : %s %s" % (field, field_type))

        if not properly_formed:
            raise CHAPIv1ArgumentError("Ill-formed argument of type %s field %s: %s" % \
                                           (field_type, field, value))
                                 

    # Check that provided values are legitimate
    def checkAllowedFields(self, field_values, field_detail_key, \
                        allowed_detail_values):

        for field in field_values:
            value = field_values[field]
            field_details = None
            if self._mandatory_fields.has_key(field):
                field_details = self._mandatory_fields[field]
            if not field_details and \
                    self._supplemental_fields.has_key(field):
                field_details = self._supplemental_fields[field]
            if not field_details:
                raise CHAPIv1ArgumentError("Unrecognized field : " + field)

            # There must be an details entry for this field in the specs
            if not field_detail_key in field_details.keys():
                raise CHAPIv1ArgumentError("Required field detail " + \
                                               " key missing for %s: %s" % \
                                               (field, field_detail_key))

            # The field detail must be one of the allowed values
            field_detail = field_details[field_detail_key]
            if field_detail not in allowed_detail_values:
                raise CHAPIv1ArgumentError("Detail Key not allowed: " + \
                                               field_detail)

    # Check that all required fields are represented in field list
    def checkRequiredFields(self, field_values, field_specs, \
                                field_detail_key, \
                                required_detail_value):

        for field_name in field_specs.keys():
            all_field_detail = field_specs[field_name]
            if all_field_detail.has_key(field_detail_key):
                field_detail = all_field_detail[field_detail_key]
                if field_detail == required_detail_value:
                    # This is a required field. Is it present?
                    if not field_name in field_values.keys():
                        raise CHAPIv1ArgumentError("Required field not provided: " + field_name)

# Lookup - 'match' [{FIELD : VALUE], {FIELD : VALUE} ...]
#        - 'filter' [FIELD, FIELD, FIELD]
class LookupArgumentCheck(FieldsArgumentCheck):

    def __init__(self, mandatory_fields, supplemental_fields):
        FieldsArgumentCheck.__init__(self, 'match', \
                                         None, \
                                         mandatory_fields, supplemental_fields)

    def validate(self, options, arguments):
        FieldsArgumentCheck.validate(self, options, arguments)

        if 'match' in options:
            self.validateFieldValueDictionary(options['match'])

        if 'filter' in options:
            self.validateFieldList(options['filter'])

# Lookup - 'match' [{FIELD : VALUE], {FIELD : VALUE} ...]
#        - 'filter' [FIELD, FIELD, FIELD]
class LookupArgumentCheckMatchOptional(FieldsArgumentCheck):

    def __init__(self, mandatory_fields, supplemental_fields):
        FieldsArgumentCheck.__init__(self, None,
                                         None, \
                                         mandatory_fields, supplemental_fields)

    def validate(self, options, arguments):
        FieldsArgumentCheck.validate(self, options, arguments)

        if 'match' in options:
            self.validateFieldValueDictionary(options['match'])

        if 'filter' in options:
            self.validateFieldList(options['filter'])

# Create - 'fields' [{FIELD : VALUE], {FIELD : VALUE} ...]
# Make sure that all other fields are {"Create" : "Allowed"}
# Make sure all required fields in the object spec are present
class CreateArgumentCheck(FieldsArgumentCheck):
    def __init__(self, mandatory_fields, supplemental_fields, argument_types=None):
        FieldsArgumentCheck.__init__(self, 'fields', \
                                         None, \
                                         mandatory_fields, supplemental_fields, argument_types)

    def validate(self, options, arguments):
        FieldsArgumentCheck.validate(self, options, arguments)

        if 'fields' in options:
            self.validateFieldList(options['fields'])
            self.validateFieldValueDictionary(options['fields'])
            self.checkAllowedFields(options['fields'], \
                                        'CREATE', \
                                        ['REQUIRED', 'ALLOWED'])
            self.checkRequiredFields(options['fields'], \
                                         self._mandatory_fields, 
                                         'CREATE', \
                                         'REQUIRED')
            self.checkRequiredFields(options['fields'], \
                                         self._supplemental_fields, 
                                         'CREATE', \
                                         'REQUIRED')
                                     
        
# Update - 'fields' [{FIELD : VALUE], {FIELD : VALUE} ...]
# For each field, check that there is an {'Update' : True} entry in 
#   object spec
class UpdateArgumentCheck(FieldsArgumentCheck):
    def __init__(self, mandatory_fields, supplemental_fields, argument_types = None):
        FieldsArgumentCheck.__init__(self, 'fields',
                                   None,
                                   mandatory_fields, supplemental_fields, argument_types)

    def validate(self, options, arguments):
        FieldsArgumentCheck.validate(self, options, arguments)

        if 'fields' in options:
            self.validateFieldList(options['fields'])
            self.validateFieldValueDictionary(options['fields'])
            self.checkAllowedFields(options['fields'], \
                                'UPDATE', \
                                [True])

# Validate only arguments, not option fields
class SimpleArgumentCheck(FieldsArgumentCheck):
    def __init__(self, argument_types):
        FieldsArgumentCheck.__init__(self, None, None, {}, {}, argument_types)

    def validate(self, options, arguments):
        self.validateArgumentFormats(arguments)

                              

class ValidURNCheck(ArgumentCheck):
    def __init__(self, urn_key) : self._urn_key = urn_key

    def validate(self, options, arguments):
        if not options.has_key(urn_key):
            raise CHAPIv1ArgumentError('Option key missing: ' + self._urn_key)
        urns = options[self._urn_key]
        if urns.instanceof(types.StringType): urns = [urns]
        for urn in urns:
            if not is_valid_urn(urn):
                raiseCHAPIv1ArgumentError("Invalid URN: " + urn)
            
