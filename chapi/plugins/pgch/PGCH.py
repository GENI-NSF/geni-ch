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
from tools.guard_utils import extract_user_urn
from tools.cert_utils import get_uuid_from_cert
from tools.chapi_log import *
import sfa.trust.gid as gid
import geni.util.urn_util as urn_util

pgch_logger = amsoil.core.log.getLogger('pgchv1')

class PGCHv1Handler(HandlerBase):

    def __init__(self):
        super(PGCHv1Handler, self).__init__(pgch_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        chapi_log_exception(PGCH_LOG_PREFIX, e)
        return super(PGCHv1Handler, self)._errorReturn(e)

    def GetVersion(self):
        method = 'GetVersion'
        args = None
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetVersion(client_cert)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)


    def GetCredential(self, args=None):
        method = 'GetCredential'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetCredential(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)

    def Resolve(self, args):
        method = 'Resolve'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.Resolve(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)

    def Register(self, args):
        method = 'Register'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.Register(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)


    def RenewSlice(self, args):
        method = 'RenewSlice'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.RenewSlice(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)

    def GetKeys(self, args):
        method = 'GetKeys'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetKeys(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
        except Exception as e:
            return self._errorReturn(e)

    def ListComponents(self, args):
        method = 'ListComponents'
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args)
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.ListComponents(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result)
            return result
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

        # If no args, get a user credential
        if not args:
            client_uuid = get_uuid_from_cert(client_cert)
            creds = []
            options = {"match" : {"MEMBER_UID" : client_uuid},
                       "fields" : ["_GENI_USER_CREDENTIAL"]}
            public_info = \
                self._ma_handler._delegate.lookup_public_member_info(creds, 
                                                                     options)
            client_urn = public_info['value'].keys()[0]
            user_credential = \
                public_info['value'][client_urn]['_GENI_USER_CREDENTIAL']
            return self._successReturn(user_credential)

#        if not args:
#            raise Exception("PGCH.Credential called with args=None")

        cred_type = None
        if 'type' in args:
            cred_type = args['type']
        if cred_type and cred_type.lower() != 'slice':
            raise Exception("PGCH.GetCredential called with type that isn't slice: %s" % \
                                cred_type)

        slice_uuid = None
        if 'uuid' in args:
            slice_uuid = args['uuid']

        slice_urn = None
        if 'urn' in args:
            slice_urn = args['urn']
            
        credentials = []
        if 'credential' in args:
            credential = args['credential']
            credentials = [credential]

        if slice_uuid and not slice_urn:
            # Lookup slice_urn from slice_uuid
            match_clause = {'SLICE_UID' : slice_uuid}
            filter_clause = ["SLICE_URN"]
            creds = []
            options = {'match' : match_clause, 'filter' : filter_clause}
            lookup_slices_return = \
                self._sa_handler._delegate.lookup_slices(client_cert, creds, options)
            if lookup_slices_return['code'] != NO_ERROR:
                return lookup_slices_return
            slice_urn = lookup_slices_return ['value'].keys()[0]

        if not slice_uuid and not slice_urn:
            raise Exception("SLICE URN or UUID not provided to PGCH.GetCredential");

        options = {}
        get_credentials_return = \
            self._sa_handler._delegate.get_credentials(client_cert, slice_urn, \
                                                           credentials, options)
        if get_credentials_return['code'] != NO_ERROR:
            return get_credentials_return

        slice_credential = get_credentials_return['value'][0]['geni_value']
        return self._successReturn(slice_credential)

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

        type = None
        if 'type' in args:
            type = args['type'].lower()
        if type not in ('slice', 'user'):
            raise Exception("Unknown type for PGH.Resolve: %s" % str(type))

        uuid = None
        if 'uuid' in args:
            uuid = args['uuid']

        urn = None
        if 'urn' in args:
            urn = args['urn']

        hrn = None
        if 'hrn' in args:
            hrn = args['hrn']

        if not hrn and not urn and not uuid:
            raise Exception("No UUID, URN or HRN identifier provided")

        if hrn and not urn:
            urn = sfa.util.xrn.hrn_to_urn(hrn, type)

        if type == 'user':
            # User
            match_clause = {'MEMBER_URN' : urn}
            if not urn:
                match_clause = {'MEMBER_UID' : uuid}
            filter_clause = \
                ['MEMBER_UID', 'MEMBER_URN', 'MEMBER_USERNAME', 'MEMBER_EMAIL', \
                     'USER_CREDENTIAL']
            identifying_filter_clause = \
                ['MEMBER_UID', 'MEMBER_URN', 'MEMBER_USERNAME', 'MEMBER_EMAIL']
            options = {"match" : match_clause, "filter" : filter_clause}
            creds = []
            lookup_public_return = \
                self._ma_handler._delegate.lookup_public_member_info(creds, 
                                                                     options)
            if lookup_public_return['code'] != NO_ERROR:
                return lookup_public_return
            public_info = lookup_public_return['value']
            this_urn = public_info.keys()[0]
            public_info = public_info[this_urn]

            lookup_identifying_return = \
                self._ma_handler._delegate.lookup_identifying_member_info(client_cert, \
                                                                              creds, options)
            if lookup_identifying_return['code'] != NO_ERROR:
                return lookup_identifying_return
            identifying_info = lookup_identifying_return['value']
            identifying_info = identifying_info[this_urn]
            

            print "LPR = " + str(lookup_public_return)
            print "LIR = " + str(lookup_identifying_return)

            member_uuid = public_info['MEMBER_UID']
            member_hrn = sfa.util.xrn.urn_to_hrn(public_info['MEMBER_URN'])[0]
            member_uuid = public_info['MEMBER_UID']
            member_email = identifying_info['MEMBER_EMAIL']
            user_gid = gid.GID(public_info['USER_CREDENTIAL'])
            member_name = public_info['MEMBER_USERNAME']

            resolve = {'uid' : member_uuid,  # login(Emulab) ID of user \
                           'hrn' : member_hrn, \
                           'uuid' : member_uuid, \
                           'email' : member_email, \
                           'gid' : user_gid.save_to_string(), # user_cred
                           'name' : member_name  # Common Name
                       }
                       
            pass
        else:
            # Slice
            match_clause = {'SLICE_URN' : urn, 'SLICE_EXPIRED' : 'f'} 
            if not urn:
                match_clause = {'SLICE_UID' : uuid}
            filter_clause = ["SLICE_UID", "SLICE_URN", "SLICE_NAME", \
                                 "_GENI_SLICE_OWNER"]
            options = {'match' : match_clause, 'filter' : filter_clause}
            creds = []
            lookup_slices_return = \
                self._sa_handler._delegate.lookup_slices(client_cert, creds, options)

            if lookup_slices_return['code'] != NO_ERROR:
                return lookup_slices_return
            slice_info_dict = lookup_slices_return['value']
            
            if len(slice_info_dict.keys()) == 0:
                raise Exception("No slice found URN %s UUID %s" % (str(urn), str(uuid)))

            slice_key = slice_info_dict.keys()[0]
            slice_info = slice_info_dict[slice_key]
            slice_name = slice_info['SLICE_NAME']
            slice_urn = slice_info['SLICE_URN']
            slice_uuid = slice_info['SLICE_UID']
            creator_uuid = slice_info['_GENI_SLICE_OWNER']

            match_clause = {'MEMBER_UID' : creator_uuid}
            filter_clause = ['MEMBER_URN']
            options = {'match' : match_clause, 'filter' : filter_clause}
            lookup_member_return = \
                self._ma_handler._delegate.lookup_public_member_info(client_cert, options)

            if lookup_member_return['code'] != NO_ERROR:
                return lookup_member_return
            creator_urn = lookup_member_return['value'].keys()[0]

            slice_cred_return = self.GetCredential(client_cert, \
                                                       {'type' : 'slice', \
                                                            'uuid' : slice_uuid})
            if slice_cred_return['code'] != NO_ERROR:
                return slice_cred_return
            slice_cred = slice_cred_return['value']
            slice_gid = gid.GID(slice_cred)

            resolve = {'urn' : slice_urn, \
                           'uuid' : slice_uuid, \
                           'creator_uuid' : creator_uuid, \
                           'creator_urn' : creator_urn,  \
                           # PG Identifier (an x509 cert) 
                           'gid' : slice_gid.save_to_string(),   \
                           'component_managers' : []
                       }
                             

        return self._successReturn(resolve)

    def Register(self, client_cert, args):
        # Omni uses this, Flack should not for our purposes
        # args are credential, hrn, urn, type
        # cred is user cred, type must be Slice
        # returns slice cred

        type = None
        if 'type' in args:
            type = args['type']
        if type and type.lower() != 'slice':
            raise Exception("PGCH.Register called with non-slice type : %s" % type)

        cred = None
        creds = []
        if 'credential' in args:
            cred = args['credential']
            creds =[cred]

        hrn = None
        if 'hrn' in args: 
            hrn = args['hrn']

        urn = None
        if 'urn' in args:
            urn = args['urn']

        if not urn and not hrn:
            raise Exception("URN or HRN required for PGCH.Register")

        if hrn and not urn:
            urn = sfa.util.xrn.hrn_to_urn(hrn, type)

        # Pull out slice name and project_name
        urn_parts = urn.split('+')
        slice_name = urn_parts[len(urn_parts)-1]
        authority = urn_parts[1]
        authority_parts = authority.split(':')
        if len(authority_parts) != 2:
            raise Exception("No project specified in slice urn: " + urn)
        authority = authority_parts[0]
        project_name = authority_parts[1]

        # Get the project_urn
        project_urn = \
            urn_util.URN(authority = authority, type = 'project', \
                             name = project_name).urn_string()

        # Set the slice email name (Bogus but consistent with current CH)
        slice_email = 'slice-%s@example.com' % slice_name

        options = {'PROJECT_URN' : project_urn, 'SLICE_NAME' : slice_name, 
                   'SLICE_EMAIL' : slice_email }

        print "OPTS = " + str(options)

        create_slice_return = \
            self._sa_handler._delegate.create_slice(client_cert, creds, options)
        if create_slice_return['code'] != NO_ERROR:
            return create_slice_return
        slice_cred = slice_create_return['value']['SLICE_CREDENTIAL']

        return self._successReturn(slice_cred)

    def RenewSlice(self, client_cert, args):
        # args are credential, expiration
        # cred is user cred
        # returns renewed slice credential
        slice_credential = args['credential']
        expiration = args['expiration']

        # Renew via update_slice in SA
        slice_urn = None
        credentials [slice_credential]
        options = {'fields' : {'SLICE_EXPIRATION' : expiration}}
        update_slice_return = \
            self._sa_handler._delegate.update_slice(client_cert, slice_urn, \
                                                        credentials, options)
        if update_slice_return['code'] != NO_ERROR:
            return update_slice_return

        get_credentials_return = \
            self._sa_handler._delegate.get_credentials(client_cert, slice_urn, \
                                                           credentials, options)
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

        options = {'match' : {'KEY_MEMBER' : member_urn},
                   "filter" : ['KEY_PUBLIC']
                   }
        ssh_keys_result = \
            self._ma_handler._delegate.lookup_keys(client_cert, creds, options)
#        print "SSH_KEYS_RESULT = " + str(ssh_keys_result)
        if ssh_keys_result['code'] != NO_ERROR:
            return ssh_keys_result

        keys = [{'type' : 'ssh' , 'key' : ssh_key['KEY_PUBLIC']} \
                    for ssh_key in ssh_keys_result['value']]
        
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

