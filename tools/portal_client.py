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

from gcf.omnilib.util.dossl import _do_ssl
import xmlrpclib
from gcf.omnilib.frameworks.framework_base import Framework_Base

# Emulate CHAPI traffic supporting specific portal pages: 
# e.g. home, projects, slices

class MAClientFramework(Framework_Base):
    def __init__(self, config, opts):
        Framework_Base.__init__(self, config)
        self.config = config
        self.logger = None
        self.fwtype = "MA Ciient"
        self.opts = opts

def emulate_portal_page(opts, verbose = False):

    suppress_errors = None
    reason = "Testing"
    config = {'cert' : opts.cert, 'key' : opts.key}

    framework = MAClientFramework(config, {})
    ma_url = opts.url
    sa_url = opts.url.replace('/MA', '/SA')
    cs_url = opts.url.replace('/MA', '/CS')
    log_url = opts.url.replace('/MA', '/LOG')
    ma_client = framework.make_client(ma_url, opts.key, opts.cert, verbose=False)
    sa_client = framework.make_client(sa_url, opts.key, opts.cert, verbose=False)
    cs_client = framework.make_client(cs_url, opts.key, opts.cert, verbose=False)
    log_client = framework.make_client(log_url, opts.key, opts.cert, verbose=False)

    if opts.page == "home":
        print "Fetching home page for %s" % opts.eppn
        # Lookup public member info by EPPN
        client_options = {'match' : {'_GENI_MEMBER_EPPN' : opts.eppn}}
        (public_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                     ma_client.lookup_public_member_info, 
                                     opts.credentials, client_options)
        member_urn = public_info['value'].keys()[0]
        member_uid = public_info['value'][member_urn]['MEMBER_UID']

        # Lookup identifying info by UID
        client_options = {'match' : {'MEMBER_UID': [member_uid]}}
        (identifying_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                          ma_client.lookup_identifying_member_info, 
                                          opts.credentials, client_options)

        # Lookup private key by UID
        client_options = {'match' : {'MEMBER_UID': [member_uid]}, 
                          'filter' : ['_GENI_MEMBER_INSIDE_PRIVATE_KEY']}
        (private_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                      ma_client.lookup_private_member_info, 
                                      opts.credentials, client_options)
        if verbose:
            print "Result = %s " % public_info
            print "Result = %s " % identifying_info
            print "Result = %s " % private_info

        # Lookup public inside cert by UID
        client_options = {'match' : {'MEMBER_UID' : [member_uid]},
                          'filter' : ['_GENI_MEMBER_INSIDE_CERTIFICATE']}
        (public_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                      ma_client.lookup_public_member_info, 
                                      opts.credentials, client_options)
        if verbose:
            print "Result = %s " % public_info

        # get_permissions
        client_options = {'_dummy' : ''}
        (permissions, msg) = _do_ssl(framework, suppress_errors, reason, 
                                      cs_client.get_permissions,
                                     member_uid, 
                                      opts.credentials, client_options)
        if verbose:
            print "Result = %s " % permissions

        # Lookup projects for member
        client_options = {'_dummy' : ''}
        (projects_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                       sa_client.lookup_projects_for_member,
                                       member_urn, 
                                       opts.credentials, client_options)
        if verbose:
            print "Result = %s " % projects_info

        # Lookup projects
        project_uids = [project_info['PROJECT_UID'] \
                            for project_info in projects_info['value']
                        if not project_info['EXPIRED']]
        client_options = {'match' : {'PROJECT_UID' : project_uids}}
        (projects, msg) = _do_ssl(framework, suppress_errors, reason, 
                                       sa_client.lookup_projects,
                                       opts.credentials, client_options)
        if verbose:
            print "Result = %s" % projects

        # Lookup slices for member
        client_options = {'_dummy' : ''}
        (slices_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                       sa_client.lookup_slices_for_member,
                                       member_urn, 
                                       opts.credentials, client_options)
        if verbose:
            print "Result = %s " % slices_info

        # Lookup slices
        slice_uids = [slice_info['SLICE_UID'] \
                            for slice_info in slices_info['value']
                      if not slice_info['EXPIRED']]
        client_options = {'match' : {'SLICE_UID' : slice_uids}}
        (slices, msg) = _do_ssl(framework, suppress_errors, reason, 
                                       sa_client.lookup_slices,
                                       opts.credentials, client_options)
        if verbose:
            print "Result = %s " % slices

        # Lookup public member info for all project leads, slice_owners
        member_uids = []
        for slice_urn, slice_data in slices['value'].items():
            if slice_data['SLICE_EXPIRED']: continue
            slice_owner_uid = slice_data['_GENI_SLICE_OWNER']
            if slice_owner_uid not in member_uids: 
                member_uids.append(slice_owner_uid)
        for project_urn, project_data in projects['value'].items():
            if project_data['PROJECT_EXPIRED']: continue
            project_lead_uid = project_data['_GENI_PROJECT_OWNER']
            if project_lead_uid not in member_uids: 
                member_uids.append(project_lead_uid)
        client_options = {'match' : {'MEMBER_UID' : member_uids}}
        (members_public_info, msg) = _do_ssl(framework, suppress_errors, reason, 
                                       ma_client.lookup_public_member_info,
                                       opts.credentials, client_options)
        if verbose:
            print "Result = %s " % members_public_info
        
        # Lookup identifying member info for all project leads, slice_owners
        client_options = {'match' : {'MEMBER_UID' : member_uids}}
        (members_identifying_info, msg) = _do_ssl(framework, 
                                                  suppress_errors, reason, 
                                                  ma_client.lookup_identifying_member_info,
                                                  opts.credentials, client_options)
        if verbose:
            print "Result = %s " % members_identifying_info

        # Lookup pending requests for user
        client_options = {'_dummy' : ''}
        (pending_requests, msg) = _do_ssl(framework, suppress_errors, reason, 
                                          sa_client.get_pending_requests_for_user,
                                          member_uid, 1, '', 
                                          opts.credentials, client_options)
        if verbose:
            print "Result = %s " % pending_requests

        # Lookup identifying member info for all project leads and slice owners
        # *** Looks like we're doing this twice...
        client_options = {'match' : {'MEMBER_UID' : member_uids}}
        (members_identifying_info, msg) = _do_ssl(framework, 
                                                  suppress_errors, reason, 
                                                  ma_client.lookup_identifying_member_info,
                                                  opts.credentials, client_options)
        if verbose:
            print "Result = %s " % members_identifying_info

        # Lookup requests by user
        client_options = {'_dummy' : ''}
        (pending_requests, msg) = _do_ssl(framework, 
                                         suppress_errors, reason, 
                                         sa_client.get_requests_by_user,
                                          member_uid, 1, '', 0,
                                         opts.credentials, client_options)
        if verbose:
            print "Result = %s " % pending_requests

        # Lookup projects for pending requests
        project_uids = []
        for pending_request in pending_requests['value']:
            project_uid = pending_request['context_id']
            project_uids.append(project_uid)
        client_options = {'match' : {'PROJECT_UID' : project_uids}}
        (pending_projects, msg) = _do_ssl(framework, 
                                         suppress_errors, reason, 
                                         sa_client.lookup_projects,
                                         opts.credentials, client_options)
        if verbose:
            print "Result = %s " % pending_projects

        # Lookup identifying info for leads of pending projects
        member_uids = []
        for pending_project_urn, pending_project_data in pending_projects['value'].items():
            lead_uid = pending_project_data['_GENI_PROJECT_OWNER']
            if lead_uid not in member_uids: member_uids.append(lead_uid)
        client_options = {'match' : {'MEMBER_UID' : member_uids}}
        (pending_project_leads, msg) = _do_ssl(framework, 
                                         suppress_errors, reason, 
                                         ma_client.lookup_identifying_member_info,
                                         opts.credentials, client_options)
        if verbose:
            print "Result = %s " % pending_project_leads

        # Lookup log entries for context
        (log_entries, msg) = _do_ssl(framework, 
                                     suppress_errors, reason, 
                                     log_client.get_log_entries_for_context,
                                     5, member_uid, 24)
            
        if verbose:
            print "Result = %s " % log_entries

        # Lookup log entries for author
        (log_entries, msg) = _do_ssl(framework, 
                                     suppress_errors, reason, 
                                     log_client.get_log_entries_by_author,
                                     member_uid, 24)
            
        if verbose:
            print "Result = %s " % log_entries


        print "Done fetching home page for %s" % opts.eppn

    else:
        print "Page not supported: %s" % page_name


