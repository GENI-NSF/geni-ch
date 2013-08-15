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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
import sfa.util.xrn
from amsoil.core import serviceinterface
from chapi.DelegateBase import DelegateBase
from chapi.HandlerBase import HandlerBase
from chapi.Exceptions import *
from ABACGuard import extract_user_urn

pgch_logger = amsoil.core.log.getLogger('pgchv1')

class PGCHv1Handler(HandlerBase):

    def __init__(self):
        super(PGCHv1Handler, self).__init__(pgch_logger)

    def GetVersion(self):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.GetVersion(client_cert)
        except Exception as e:
            return self._errorReturn(e)


    def GetCredential(self, args=None):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.GetCredential(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)

    def Resolve(self, args):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.Resolve(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)

    def Register(self, args):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.Register(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)


    def RenewSlice(self, args):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.RenewSlice(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)

    def GetKeys(self, args):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.GetKeys(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)

    def ListComponents(self, args):
        try:
            client_cert = self.requestCertificate()
            return self._delegate.ListComponents(client_cert, args)
        except Exception as e:
            return self._errorReturn(e)

class PGCHv1Delegate(DelegateBase):

    def __init__(self):
        super(PGCHv1Delegate, self).__init__(pgch_logger)
        self._ch_handler = pm.getService('chv1handler')
        self._sa_handler = pm.getService('sav1handler')
        self._ma_handler = pm.getService('mav1handler')

    def GetVersion(self, client_cert):

        # Values returned by GetVersion
        API_VERSION = 1.3
        CODE_VERSION = "0001"
        CH_HOSTNAME = "ch.geni.net"
        CH_PORT = "8443"

        self.logger.info("Called GetVersion")
        version = dict()

        peers = dict() # FIXME: This is the registered CMs at PG Utah
        version['peers'] = peers
        version['api'] = API_VERSION
        version['urn'] = 'urn:publicid:IDN+' + CH_HOSTNAME + '+authority+ch'
        version['hrn'] = CH_HOSTNAME
        version['url'] = 'https://' + CH_HOSTNAME + ':' + CH_PORT
        version['interface'] = 'registry'
        version['code_tag'] = CODE_VERSION
        version['hostname'] = CH_HOSTNAME
        version['gcf-pgch_api'] = API_VERSION

        return self._successReturn(version)

        # Note that the SA GetVersion is not implemented
        # return value should be a struct with a bunch of entries
        return self._ch_handler.get_version()

    def GetCredential(self, client_cert, args):
        # all none means return user cred
        # else cred is user cred, id is uuid or urn of object, type=Slice
        #    where omni always uses the urn
        # return is slice credential
        #args: credential, type, uuid, urn
        # *** WRITE ME ***
        return self._successReturn("GetCredential" + str(args))

    def Resolve(self, client_cert, args):
        # Omni uses this, Flack may not need it

        # ID may be a uuid, hrn, or urn
        #   Omni uses hrn for type=User, urn for type=Slice
        # type is Slice or User
        # args: credential, hrn, urn, uuid, type
        # Return is dict:
#When the type is Slice:
#
#{
#  "urn"  : "URN of the slice",
#  "uuid" : "rfc4122 universally unique identifier",
#  "creator_uuid" : "UUID of the user who created the slice",
#  "creator_urn" : "URN of the user who created the slice",
#  "gid"  : "ProtoGENI Identifier (an x509 certificate)",
#  "component_managers" : "List of CM URNs which are known to contain slivers or tickets in this slice. May be stale"
#}
#When the type is User:
#
#{
#  "uid"  : "login (Emulab) ID of the user.",
#  "hrn"  : "Human Readable Name (HRN)",
#  "uuid" : "rfc4122 universally unique identifier",
#  "email": "registered email address",
#  "gid"  : "ProtoGENI Identifier (an x509 certificate)",
#  "name" : "common name",
#}
        # *** WRITE ME ***
        return self._successReturn("Resolve" + str(args))

    def Register(self, client_cert, args):
        # Omni uses this, Flack should not for our purposes
        # args are credential, hrn, urn, type
        # cred is user cred, type must be Slice
        # returns slice cred
        # *** WRITE ME ***
        return self._successReturn("Register"  + str(args))

    def RenewSlice(self, client_cert, args):
        # args are credential, expiration
        # cred is user cred
        # returns renewed slice credential
        slice_credential = args['credential']
        expiration = args['expiration']

        # *** Need to support update_slice in SA
        slice_urn = None
        credentials [slice_credential]
        options = {'fields' : {'SLICE_EXPIRATION' : expiration}}
        update_slice_return = \
            self._sa_handler.update_slice(slice_urn, credentials, options)
        if update_slice_return['code'] != NO_ERROR:
            return update_slice_return

        # *** Need to support get_credentials  in SA
        get_credentials_return = \
            self._sa_handler.get_credentials(slice_urn, credentials, options)
        if get_credentials_return['code'] != NO_ERROR:
            return get_credentials_return
        renewed_slice_credentials = get_credentials_return['value']

        return self._successReturn("RenewSlice" + str(args))

    def GetKeys(self, client_cert, args):
        # cred is user cred
        # return list( of dict(type='ssh', key=$key))
        # args: credential

        self.logger.info("Called GetKeys")

        credential = args['credential']
        creds = [credential]

        member_urn = extract_user_urn(client_cert)

        options = {'match' : {'MEMBER_URN' : member_urn}}
        member_info_result = \
            self._ma_handler.lookup_public_member_info(creds, options)
        if member_info_result['code'] != NO_ERROR:
            return member_info_result
        member_info = member_info_result['value']
        keys = []
        for member_urn in member_info.keys():
            member = member_info[member_urn]
            ssh_key = member['MEMBER_SSH_PUBLIC_KEY']
            ssh_key_dict = {'type' : 'ssh', 'key' : ssh_key}
            keys.append(ssh_key_dict)
        
        return self._successReturn(keys)


    def ListComponents(self, client_cert, args):
        # Returns list of CMs (AMs)
        # cred is user cred or slice cred - Omni uses user cred
        # return list( of dict(gid=<cert>, hrn=<hrn>, url=<AM URL>))
        # Matt seems to say hrn is not critical, and can maybe even skip cert
        # args: credential

        self.logger.info("Called ListComponents")
        options = dict()
        get_aggregates_result = self._ch_handler.get_aggregates(options)
        if get_aggregates_result['code'] != NO_ERROR:
            return get_aggregates_result
        aggregates = get_aggregates_result['value']
        components = []
        for aggregate in aggregates:
            cert_file = aggregate['SERVICE_CERTIFICATE']
            gid = open(cert_file).read()
            urn = aggregate['SERVICE_URN']
            hrn = sfa.util.xrn.urn_to_hrn(urn)
            url = aggregate['SERVICE_URL']
            component = {'gid' : gid, 'hrn' : hrn, 'url' : url}
            components.append(component)
        return self._successReturn(components)

