#----------------------------------------------------------------------
# Copyright (c) 2012-2015 Raytheon BBN Technologies
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

# Library of tools for communicating with the GENI clearinghouse
# (CHAPI) services via XML/RPC.
#
# Client-side SSL authentication solution for xmlrpclib is inspired by the discussion
# in https://groups.google.com/forum/#!topic/comp.lang.python/seSFYP0Y-o0
#
import xmlrpclib
import uuid
from tempfile import mkstemp
import os
import sys

class SafeTransportWithCert(xmlrpclib.SafeTransport):
    def __init__(self, cert, key):
        #xmlrpclib.SafeTransport.__init__(self)
        xmlrpclib.Transport.__init__(self)
        _, cert_file = mkstemp()
        cfd = open(cert_file, "w")
        cfd.write(cert)
        cfd.close()
        self._cert_file = cert_file
        _, key_file = mkstemp()
        kfd = open(key_file, "w")
        kfd.write(key)
        kfd.close()
        self._key_file = key_file

    def __del__(self):
        os.remove(self._cert_file)
        os.remove(self._key_file)

    def make_connection(self,host):
        host_with_cert = (host, { 'key_file'  :  self._key_file,
                                  'cert_file' :  self._cert_file
                                  } )
        return xmlrpclib.SafeTransport.make_connection(self, host_with_cert)

def make_proxy(url, cert, key):
    return xmlrpclib.ServerProxy(url, transport=SafeTransportWithCert(cert, key), allow_none=True)

def service_url(url, suffix):
    '''Make sure that the url has the right suffix'''
    return url+'/'+suffix;

def is_urn(s):
    '''return the string IFF the passed string is a URN, else False'''
    if s.startswith('urn:'):
        return s
    else:
        return False

def is_UUID(s):
    '''return the string IFF the passed argument is a UUID, else False'''
    try:
        uuid.UUID(s)
        return s
    except ValueError:
        return False

def is_email(s):
    '''return the string IFF the passed argument is an email address, else False'''
    stuff = s.split('@')
    if len(stuff) == 2:
        return s
    else:
        return False

def find_member_id(member, url, logger, cert, pkey):
    if is_UUID(member):
        return member

    proxy = make_proxy(url, cert, pkey)

    if is_urn(member):
        result = proxy.lookup_public_member_info([],
                                                 { 'match': {'MEMBER_URN': member},
                                                   'filter': ['MEMBER_UID'] })
    elif is_email(member):
        # in CHAPI, email is identifying, so this won't work unless we have ops rights
        result = proxy.lookup_identifying_member_info([],
                                                      { 'match': {'MEMBER_EMAIL': member},
                                                        'filter': ['MEMBER_UID'] })
    else:
        # otherwise, assume a username
        result = proxy.lookup_public_member_info([],
                                                 { 'match': {'MEMBER_USERNAME': member},
                                                   'filter': ['MEMBER_UID'] })

    if not 'code' in result:
        return None
    status = result['code']
    if not status == 0:
        sys.stderr.write(result['output']+"\n")
        return None
    matches = result['value']
    if not matches or len(matches) < 1:
        return None
    first_match = matches.values()[0]
    member_id = first_match['MEMBER_UID'] #'member_id'

    return member_id

def find_member_urn(member, url, cert, pkey):
    if is_urn(member):
        return member

    # TODO: In the future, try to figure out if 'member' is a URN or email address
    proxy = make_proxy(url, cert, pkey)

    if is_UUID(member):
        result = proxy.lookup_public_member_info([],
                                                 { 'match': {'MEMBER_UID': member},
                                                   'filter': ['MEMBER_URN'] })
    elif is_email(member):
        # in CHAPI, email is identifying, so this won't work unless we have ops rights
        result = proxy.lookup_identifying_member_info([],
                                                      { 'match': {'MEMBER_EMAIL': member},
                                                        'filter': ['MEMBER_URN'] })
    else:
        # otherwise, assume a username
        result = proxy.lookup_public_member_info([],
                                                 { 'match': {'MEMBER_USERNAME': member},
                                                   'filter': ['MEMBER_URN'] })

    if not 'code' in result:
        return None
    status = result['code']
    if not status == 0:
        return None
    matches = result['value']
    if not matches or len(matches) < 1:
        return None
    first_match = matches.values()[0]
    member_urn = first_match['MEMBER_URN'] #'member_id'
    if not is_urn(member_urn):
        return None
    return member_urn

def find_project_param(project, url, cert, pkey, param):
    if is_urn(project):
        key = 'PROJECT_URN'
    elif is_UUID(project):
        key = 'PROJECT_UID'
    else:
        key = 'PROJECT_NAME'

    # short circuit if it is already what we want
    if key == param:
        return project

    proxy = make_proxy(url, cert, pkey)
    result = proxy.lookup_projects([], {'match': {key: project}})
    result_code = result['code']
    result_value = result['value']
    if result_code == 0 and result_value and len(result_value)>0:
        result = result_value.values()[0][param]
        return result
    else:
        raise Exception("Invalid project identifier %r" % (project))

def find_project_urn(project, url, cert, pkey):
    return find_project_param(project, url, cert, pkey, 'PROJECT_URN')

def find_project_id(project, url, cert, pkey):
    return find_project_param(project, url, cert, pkey, 'PROJECT_UID')

def find_slice_urn(slice, url, cert, pkey):
    if is_urn(slice):
        return slice
    if is_UUID(slice):
        key = 'SLICE_UID'
    else:
        key = 'SLICE_NAME'
    proxy = make_proxy(url, cert, pkey)
    result = proxy.lookup_slices([], {'match': {key: slice}})
    result_code = result['code']
    result_value = result['value']
    if result_code == 0 and result_value and len(result_value)>0:
        result = result_value.values()[0]['SLICE_URN']    #['slice_id']
        print "slice_id = "+result
        return result
    else:
        raise Exception("Invalid slice name or uuid %r" % (slice))
