#!/usr/bin/env python
# ----------------------------------------------------------------------
# Copyright (c) 2013-2016 Raytheon BBN Technologies
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
# ----------------------------------------------------------------------

import os
import os.path
import sys
import json
import optparse
from gcf.omnilib.util.dossl import _do_ssl
import xmlrpclib
import logging
from gcf.omnilib.frameworks.framework_base import Framework_Base
from portal_client import *
from geni_constants import *


# Generic client to speak XMLRPC/SSL SA/CH/MA API calls to

class MAClientFramework(Framework_Base):
    def __init__(self, config, opts):
        Framework_Base.__init__(self, config)
        self.config = config
        self.logger = logging.getLogger('client')
        self.fwtype = "MA Ciient"
        self.opts = opts


def parseOptions(args):
    parser = optparse.OptionParser()

    home = os.getenv('HOME')
    gcf_home = os.path.join(home, '.gcf')

    parser.add_option("--url", help="Server URL", default=None)
    parser.add_option("--type", help="Object Type for generic v2 calls",
                      default=None)
    parser.add_option("--urn", help="URN for API arguments", default=None)
    parser.add_option("--key", help="Location of user key",
                      default=os.path.join(gcf_home, 'alice-key.pem'))
    parser.add_option("--cert", help="Location of user cert",
                      default=os.path.join(gcf_home, 'alice-cert.pem'))
    parser.add_option("--method", help="Name of method to invoke",
                      default="get_version")
    helpMsg = 'Name of portal page to simulate (home, projects, slices)'
    parser.add_option("--page", help=helpMsg)
    parser.add_option("--eppn", help="EPPN of user")
    parser.add_option("--agg_url", help="URL of aggregate in some API calls",
                      default=None)
    parser.add_option("--string_arg", help="String argument for some calls",
                      default=None)
    parser.add_option("--string2_arg",
                      help="second string argument for some calls",
                      default=None)
    parser.add_option("--int_arg", help="Integer argument for some calls",
                      type='int', default=None)
    parser.add_option("--int2_arg",
                      help="second integer argument for some calls",
                      type='int', default=None)
    parser.add_option("--int3_arg",
                      help="third integer argument for some calls",
                      type='int', default=None)
    parser.add_option("--uuid_arg", help="UUID argument for some calls",
                      default=None)
    parser.add_option("--uuid2_arg",
                      help="second UUID argument for some calls",
                      default=None)
    parser.add_option("--uuid3_arg", help="third UUID argument for some calls",
                      default=None)
    parser.add_option("--file_arg", help="FILE argument for some calls",
                      default=None)
    parser.add_option("--options", help="JSON of options argument",
                      default="{}")
    parser.add_option("--options_file",
                      help="File containing JSON of options argument",
                      default=None)
    parser.add_option("--attributes", help="JSON of attributes argument",
                      default="{}")
    parser.add_option("--attributes_file",
                      help="File containing JSON of attributes argument",
                      default=None)
    parser.add_option("--credentials",
                      help="List of comma-separated credential files",
                      default="")
    parser.add_option("--raw_output", action="store_true", 
                      dest="raw_output", default=False)

    [opts, args] = parser.parse_args(args)
    if len(opts.credentials) > 0:
        cred_structs = []
        credentials = "".join(opts.credentials.split())
        credentials = credentials.split(',')
        for credential in credentials:
            cred_parts = credential.split(':')
            cred_file = cred_parts[0]
            cred_type = cred_parts[1]
            cred_data = open(cred_file).read()
            cred_struct = {'geni_type': cred_type, 'geni_version': 1,
                           'geni_value': cred_data}
            cred_structs.append(cred_struct)
        opts.credentials = cred_structs
    else:
        opts.credentials = []

    if opts.url is None:
        raise Exception("URL is required argument")

    return opts, args


def add_attribute(attributes, int_arg, uuid_arg):
    if int_arg == PROJECT_CONTEXT and uuid_arg:
        attributes['PROJECT'] = uuid_arg
    elif int_arg == SLICE_CONTEXT and uuid_arg:
        attributes['SLICE'] = uuid_arg


def main(args=sys.argv, do_print=True):
    logging.basicConfig()
    opts, args = parseOptions(args)
    client_options = json.loads(opts.options)
    if opts.options_file:
        client_options = json.load(open(opts.options_file, 'r'))
    client_attributes = json.loads(opts.attributes)
    if opts.attributes_file:
        client_attributes = json.load(open(opts.attributes_file, 'r'))
    if do_print and not opts.raw_output:
        print "CREDS = " + str(opts.credentials)
        print "OPTIONS = " + str(client_options)
    suppress_errors = None
    reason = "Testing"
    config = {'cert': opts.cert, 'key': opts.key}

    framework = MAClientFramework(config, {})
    client = framework.make_client(opts.url, opts.key, opts.cert,
                                   allow_none=True,
                                   verbose=False)
    fcn = getattr(client, opts.method)

    # Methods that take no arguments
    result = None
    msg = None

    if opts.page:
        emulate_portal_page(opts)

    elif opts.method in ['get_version', 'get_trust_roots']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn)
    # Methods that take options argument
    elif opts.method in ['lookup_member_authorities',
                         'lookup_slice_authorities',
                         'lookup_aggregates',
                         'lookup_authorities_for_urns']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                client_options)
    # Methods that take a URN and an aggregate URL argument
    elif opts.method in ['register_aggregate', 'remove_aggregate'] and \
            opts.agg_url:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.urn, opts.agg_url, opts.credentials,
                                client_options)
    elif (opts.int_arg is not None and
          opts.method in ['get_services_of_type', 'get_first_service_of_type',
                          'get_service_by_id']):
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                int(opts.int_arg))
    elif opts.method in ['get_services']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn)
    # Logging methods (test)
    elif opts.method in ['log_event']:
        message = opts.string_arg
        attributes = {}
        add_attribute(attributes, opts.int_arg, opts.uuid_arg)
        add_attribute(attributes, opts.int2_arg, opts.uuid2_arg)
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                message, attributes, opts.credentials,
                                client_options)
    elif opts.method in ['get_log_entries_by_author']:
        num_hours = 15 * 24
        user_id = '8e405a75-3ff7-4288-bfa5-111552fa53ce'
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                user_id, num_hours, opts.credentials,
                                client_options)
    elif opts.method in ['get_log_entries_for_context']:
        context_type = 'SLICE'
        context_id = '848e4a11-55eb-45df-a0e8-b79109fb0a88'
        num_hours = 15 * 24
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                context_type, context_id, num_hours,
                                opts.credentials, client_options)
    elif opts.method in ['get_log_entries_by_attributes']:
        type1 = 'SLICE'
        id1 = '848e4a11-55eb-45df-a0e8-b79109fb0a88'
        type2 = 'PROJECT'
        id2 = '8c042cf0-8389-48e0-aca1-782fd7a20794'
        num_hours = 15 * 24
        attribute_sets = [{type1: id1}, {type2: id2}]
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                attribute_sets, num_hours, opts.credentials,
                                client_options)

    elif opts.method in ['get_attributes_for_log_entry']:
        event_id = '20360'
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                event_id, opts.credentials,
                                client_options)
    # Credential store methods
    elif opts.method in ['get_permissions']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.uuid_arg,
                                opts.credentials, client_options)
    elif opts.method in ['get_attributes']:
        context = 'None'
        if opts.uuid2_arg:
            context = opts.uuid2_arg
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.uuid_arg,
                                opts.int_arg, context,
                                opts.credentials, client_options)
    elif opts.method in ['lookup_keys']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.credentials, client_options)
    elif opts.method in ['delete_key', 'update_key'] \
            and opts.string_arg and opts.urn:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.string_arg,
                                opts.credentials, client_options)

    # Client Authorization methods
    elif opts.method in ['list_clients']:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn)
    elif opts.method in ['list_authorized_clients']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.uuid_arg)
    elif opts.method in ['authorize_client']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.uuid_arg,
                    opts.urn, opts.int_arg)
    # Sliver info methods
    elif opts.method in ['delete_sliver_info', 'update_sliver_info']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.urn,
                    opts.credentials, client_options)
    elif opts.method in ['create_sliver_info', 'lookup_sliver_info']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn,
                    opts.credentials, client_options)

    # Project request methods
    elif opts.method in ['create_request']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.int_arg,
                    opts.uuid_arg, opts.int2_arg, opts.string_arg,
                    opts.string2_arg,
                    opts.credentials, client_options)
    elif opts.method in ['resolve_pending_request']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.int_arg,
                    opts.int2_arg, opts.int3_arg, opts.string_arg,
                    opts.credentials, client_options)
    elif opts.method in ['invite_member']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.int_arg,
                    opts.uuid_arg,
                    opts.credentials, client_options)

    elif opts.method in ['accept_invitation']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn,
                    opts.uuid_arg,  # invite_id
                    opts.uuid2_arg,  # member_id
                    opts.credentials, client_options)

    elif opts.method in ['get_requests_for_context']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.int_arg,
                    opts.uuid_arg, opts.int2_arg, opts.credentials,
                    client_options)
    elif opts.method in ['get_requests_by_user']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.uuid_arg,
                    opts.int_arg, opts.uuid2_arg, opts.int2_arg,
                    opts.credentials, client_options)
    elif opts.method in ['get_pending_requests_for_user',
                         'get_number_of_pending_requests_for_user']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.uuid_arg,
                    opts.int_arg, opts.uuid2_arg, opts.credentials,
                    client_options)

    elif opts.method in ['get_request_by_id']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn,
                    opts.int_arg, opts.int2_arg, opts.credentials,
                    client_options)

    # MA certificate methods
    elif opts.method in ['create_certificate']:
        options = {}
        if opts.file_arg:
            csr = open(opts.file_arg).read()
            options = {'csr': csr}
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.urn,
                    opts.credentials, options)

    # Method to create members
    elif opts.method in ['create_member'] and opts.string_arg:

        # Use the entered string_arg as the email to register a member
        attributes = [{"value": opts.string_arg,
                       "name": "email_address",
                       "self_asserted": False}]
        options = {}

        # Send query message and retrieve the result and response message
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                attributes, opts.credentials, options)

    # Method to lookup for members
    elif opts.method in ['lookup_public_member_info',
                         'lookup_private_member_info',
                         'lookup_allowed_member_info',
                         'lookup_identifying_member_info'] and \
            (opts.urn or opts.uuid_arg):

        # Create client options dictionary
        client_options = {"match": {}}

        # If the user entered an UUID
        if opts.uuid_arg:
            # Uptade the client options dictionary with the entered UUID
            client_options["match"].update({"MEMBER_UID": opts.uuid_arg})

        # If the user entered an URN
        if opts.urn:
            # Uptade the client options dictionary with the entered URN
            client_options["match"].update({"MEMBER_URN": opts.urn})

        # Send query message and retrieve the result and response message
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.credentials, client_options)

    # MA add/revoke privilege methods
    elif opts.method in ['add_member_privilege', 'revoke_member_privilege']:
        options = {}
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.uuid_arg,
                    opts.string_arg,
                    opts.credentials, options)

    # Methods that take urn, credentials, options
    elif opts.method in ['get_credentials']:
        options = {}
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.urn,
                    opts.credentials, options)

    # Generic Federation v2 API methods
    elif opts.method in ['lookup', 'create']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.type,
                    opts.credentials, client_options)

    elif opts.method in ['update', 'delete', 'modify_membership',
                         'lookup_members', 'lookup_for_member']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, opts.type,
                    opts.urn, opts.credentials, client_options)

    # Lookup login info (authorities only)
    elif opts.method in ['lookup_login_info']:
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn, 
                    opts.credentials, client_options)

    # Portal query
    elif opts.method in ['portal_query']:
        options = {}
        member_eppn = opts.string_arg
        project_id = opts.uuid_arg
        slice_id = opts.uuid2_arg
        (result, msg) = \
            _do_ssl(framework, suppress_errors, reason, fcn,
                    member_eppn, project_id, slice_id)

    # Methods that take attributes and options
    elif client_attributes:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                client_attributes,
                                opts.credentials, client_options)

    # Methods that take credentials and options and urn arguments
    elif opts.urn:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.urn,
                                opts.credentials, client_options)
    # Methods that take credentials and options (and no urn) arguments
    else:
        (result, msg) = _do_ssl(framework, suppress_errors, reason, fcn,
                                opts.credentials, client_options)

    if do_print:
        if opts.raw_output:
            print json.dumps(result)
        else:
            print "RESULT = " + str(result)
        if msg:
            print "MSG = " + str(msg)

if __name__ == "__main__":
    sys.exit(main())
