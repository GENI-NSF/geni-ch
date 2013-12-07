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
from tools.cert_utils import get_uuid_from_cert, get_urn_from_cert, get_email_from_cert
from tools.chapi_log import *
import sfa.trust.gid as gid
import geni.util.urn_util as urn_util

pgch_logger = amsoil.core.log.getLogger('pgchv1')

class PGCHv1Handler(HandlerBase):

    def __init__(self):
        super(PGCHv1Handler, self).__init__(pgch_logger)

    # Override error return to log exception
    def _errorReturn(self, e):
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_exception(PGCH_LOG_PREFIX, e, {'user': user_email})
        return super(PGCHv1Handler, self)._errorReturn(e)

    def GetVersion(self):
        method = 'GetVersion'
        args = None
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetVersion(client_cert)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)


    def GetCredential(self, args=None):
        method = 'GetCredential'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetCredential(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)

    def Resolve(self, args):
        method = 'Resolve'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.Resolve(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)

    def Register(self, args):
        method = 'Register'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.Register(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)


    def RenewSlice(self, args):
        method = 'RenewSlice'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.RenewSlice(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)

    def GetKeys(self, args):
        method = 'GetKeys'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.GetKeys(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
            return result
        except Exception as e:
            return self._errorReturn(e)

    def ListComponents(self, args):
        method = 'ListComponents'
        user_email = get_email_from_cert(self.requestCertificate())
        chapi_log_invocation(PGCH_LOG_PREFIX, method, [], {}, args, {'user': user_email})
        try:
            client_cert = self.requestCertificate()
            result = self._delegate.ListComponents(client_cert, args)
            chapi_log_result(PGCH_LOG_PREFIX, method, result, {'user': user_email})
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
        self.logger.info("Called GetVersion")

        user_email = get_email_from_cert(client_cert)
        # Load the authority from the config
        config = pm.getService('config')
        authority = config.get('chrm.authority')

        # Which API? What is the right value?
        API_VERSION = 1
        CH_HOSTNAME = authority

        # Read code tag from a file
        code_tag_file = '/etc/geni-chapi/geni-chapi-githash'
        try:
            with open(code_tag_file, 'r') as f:
                code_tag = f.readline().strip()
        except:
            msg = 'GetVersion: Cannot read code tag file %r.'
            msg = msg % (code_tag_file)
            chapi_error(PGCH_LOG_PREFIX, msg, {'user': user_email})
            code_tag = 'unknown'

        # Templated URN. Should we get this from
        # the authority certificate?
        urn = 'urn:publicid:IDN+' + CH_HOSTNAME + '+authority+ch'

        # At present there are no peers
        peers = dict()
        version = dict(peers=peers,
                       api=API_VERSION,
                       urn=urn,
                       hrn=CH_HOSTNAME,
                       url='https://' + CH_HOSTNAME + '/PGCH',
                       interface='registry',
                       code_tag=code_tag,
                       hostname=CH_HOSTNAME)
        return self._successReturn(version)

    def GetCredential(self, client_cert, args):
        # all none means return user cred
        # else cred is user cred, id is uuid or urn of object, type=Slice
        #    where omni always uses the urn
        # return is slice credential
        #args: credential, type, uuid, urn

        user_email = get_email_from_cert(client_cert)
        # If no args, get a user credential
        if not args:
#             client_uuid = get_uuid_from_cert(client_cert)
#             creds = []
#             options = {"match" : {"MEMBER_UID" : client_uuid},
#                        "fields" : ["_GENI_USER_CREDENTIAL"]}
#             public_info = \
#                 self._ma_handler._delegate.lookup_public_member_info(client_cert, creds, 
#                                                                      options)
#             client_urn = public_info['value'].keys()[0]
#             user_credential = \
#                 public_info['value'][client_urn]['_GENI_USER_CREDENTIAL']

            client_urn = get_urn_from_cert(client_cert)
            creds = self._ma_handler.get_credentials(client_urn, [], {})
            if creds['code'] != NO_ERROR: return creds

            # Extract the SFA user credential from the returned set
            user_credential = None
            for cred in creds['value']:
                if cred['geni_type'] == 'geni_sfa':
                    user_credential = cred['geni_value']
                    break

            if user_credential is None:
                msg = "User %s got no user credential for cert %s" % (client_urn, client_cert[:250])
                chapi_warn(PGCH_LOG_PREFIX, msg,
                          {'user': user_email})
                raise CHAPIv1ServerError(msg)

            return self._successReturn(user_credential)

#        if not args:
#            raise Exception("PGCH.Credential called with args=None")

        cred_type = None
        if 'type' in args:
            cred_type = args['type']
        if cred_type and cred_type.lower() != 'slice':
            raise CHAPIv1ArgumentError("PGCH.GetCredential called with type that isn't slice: %s" % \
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
            # FIXME: SFA or geni_sfa?
            if isinstance(credential, str) or isinstance(credential, unicode):
                credentials = [{'geni_type': 'SFA', 'geni_value': credential}] 

        if slice_uuid and not slice_urn:
            # Lookup slice_urn from slice_uuid
            match_clause = {'SLICE_UID' : slice_uuid}
            filter_clause = ["SLICE_URN"]
            creds = []
            options = {'match' : match_clause, 'filter' : filter_clause}
            lookup_slices_return = \
                self._sa_handler.lookup_slices(creds, options)
            if lookup_slices_return['code'] == AUTHORIZATION_ERROR:
                msg = "No slice found for uid %s" % slice_uuid
                chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
                # Return an error with this message
                return { 'code' :  ARGUMENT_ERROR , 'value' : "", 'output' : msg }

            if lookup_slices_return['code'] != NO_ERROR:
                return lookup_slices_return
            if not lookup_slices_return or \
                    not lookup_slces_return['value'] or \
                    len(lookup_slces_return['value'].keys()) == 0:
                msg = "No slice found for uid %s" % slice_uuid
                chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
                # Return an error with this message
                return { 'code' :  ARGUMENT_ERROR , 'value' : "", 'output' : msg }

            slice_urn = lookup_slices_return ['value'].keys()[0]

        if not slice_uuid and not slice_urn:
            raise CHAPIv1ArgumentError("SLICE URN or UUID not provided to PGCH.GetCredential");

        options = {}
        get_credentials_return = \
            self._sa_handler.get_credentials(slice_urn, \
                                                           credentials, options)
        if get_credentials_return['code'] == AUTHORIZATION_ERROR:
            msg = "No slice found for urn %s" % slice_urn
            chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
            # Return an error with this message
            return { 'code' :  ARGUMENT_ERROR , 'value' : "", 'output' : msg }

        if get_credentials_return['code'] != NO_ERROR:
            return get_credentials_return

        if not get_credentials_return['value'] or \
                len(get_credentials_return['value']) == 0:
            msg = "No slice found for urn %s" % slice_urn
            chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
            # Return an error with this message
            return { 'code' :  ARGUMENT_ERROR , 'value' : "", 'output' : msg }
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

        user_email = get_email_from_cert(client_cert)
        type = None
        if 'type' in args:
            type = args['type'].lower()
        if type not in ('slice', 'user'):
            raise CHAPIv1ArgumentError("Unknown type for PGH.Resolve: %s" % str(type))

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
            raise CHAPIv1ArgumentError("No UUID, URN or HRN identifier provided")

        if hrn and not urn:
            urn = sfa.util.xrn.hrn_to_urn(hrn, type)

        if type == 'user':
            # User
            ma = self._ma_handler
            match_clause = {'MEMBER_URN' : urn}
            if not urn:
                match_clause = {'MEMBER_UID' : uuid}
            public_filter_clause = ['MEMBER_UID', 'MEMBER_URN',
                                    'MEMBER_USERNAME',
                                    '_GENI_MEMBER_SSL_CERTIFICATE']
            public_options = {"match" : match_clause,
                              "filter" : public_filter_clause}
            creds = []
            lookup_public_return = \
                ma.lookup_public_member_info(creds, public_options)
            if lookup_public_return['code'] != NO_ERROR:
                return lookup_public_return
            public_info = lookup_public_return['value']
            if not public_info or len(public_info.keys()) == 0 or \
                    (urn and not public_info.has_key(urn)):
                # no user by that urn or uuid
                msg = ""
                if urn:
                    msg = "User requested not found: %s" % urn
                else:
                    msg = "User requested not found: %s" % uuid

                chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
                # Return an error with this message
                return { 'code' :  ARGUMENT_ERROR , 'value' : {}, 'output' : msg }

            this_urn = public_info.keys()[0]
            public_info = public_info[this_urn]

            identifying_filter_clause = ['MEMBER_EMAIL']
            identifying_options = {'match' : match_clause,
                                   'filter' : identifying_filter_clause }
            lookup_identifying_return = \
                ma.lookup_identifying_member_info(creds,
                                                  identifying_options)
            if lookup_identifying_return['code'] != NO_ERROR:
                return lookup_identifying_return
            identifying_info = lookup_identifying_return['value']
            identifying_info = identifying_info[this_urn]

            member_uuid = public_info['MEMBER_UID']
            member_hrn = sfa.util.xrn.urn_to_hrn(public_info['MEMBER_URN'])[0]
            member_uuid = public_info['MEMBER_UID']
            member_email = identifying_info['MEMBER_EMAIL']
            member_gid = public_info['_GENI_MEMBER_SSL_CERTIFICATE']
            member_name = public_info['MEMBER_USERNAME']

            # Slices
            sa = self._sa_handler
            lookup_slices_return = sa.lookup_slices_for_member(
                                                               urn, [], {})
            if lookup_slices_return['code'] != NO_ERROR:
                return lookup_slices_return
            slice_info = lookup_slices_return['value']
            slices = []
            for s in slice_info:
                if s['EXPIRED'] == True:
                    continue
                slices.append(s['SLICE_URN'])

            resolve = {'uid' : member_uuid,  # login(Emulab) ID of user \
                           'hrn' : member_hrn, \
                           'uuid' : member_uuid, \
                           'email' : member_email, \
                           'gid' : member_gid,
                           'name' : member_name,  # Common Name
                       'slices' : slices
                       }
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
                self._sa_handler.lookup_slices(creds, options)

            if lookup_slices_return['code'] != NO_ERROR:
                return lookup_slices_return
            slice_info_dict = lookup_slices_return['value']
            
            if len(slice_info_dict.keys()) == 0:
                msg = ""
                if urn:
                    msg = "No slice found URN %s" % str(urn)
                else:
                    msg = "No slice found UID %s" % str(uuid)
                chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
                return { 'code' : ARGUMENT_ERROR, 'value': {}, 'output': msg}

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
                self._ma_handler.lookup_public_member_info(creds, options)

            if lookup_member_return['code'] != NO_ERROR:
                return lookup_member_return
            # If the slice owner listed is not in the DB this will
            # give an error, but that is also a DB error
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

        user_email = get_email_from_cert(client_cert)
        type = None
        if 'type' in args:
            type = args['type']
        if type and type.lower() != 'slice':
            raise CHAPIv1ArgumentError("PGCH.Register called with non-slice type : %s" % type)

        cred = None
        creds = []
        if 'credential' in args:
            cred = args['credential']
            creds = [cred]
            # FIXME: SFA or geni_sfa?
            if isinstance(cred, str) or isinstance(cred, unicode):
                creds = [{'geni_type': 'SFA', 'geni_value': cred}] 

        hrn = None
        if 'hrn' in args: 
            hrn = args['hrn']

        urn = None
        if 'urn' in args:
            urn = args['urn']

        if not urn and not hrn:
            raise CHAPIv1ArgumentError("URN or HRN required for PGCH.Register")

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

        options = {'fields': {'SLICE_PROJECT_URN' : project_urn,
                              'SLICE_NAME' : slice_name,
                              '_GENI_SLICE_EMAIL' : slice_email }}

        sa = self._sa_handler
        create_slice_return = sa.create_slice(creds, options)

        # FIXME: A bad project name results in an authorization error
        # You'd also get that if you were an auditor in the project or
        # not a member at all
        if create_slice_return['code'] == AUTHORIZATION_ERROR:
            # Maybe try to look up the project for me?
            msg = "User not authorized to create slice %s in project %s. Check the project name." % (slice_name, project_name)
            chapi_info(PGCH_LOG_PREFIX, msg, {'user': user_email})
            return {'code': AUTHORIZATION_ERROR, 'value': "",
                    'output': msg}
        if create_slice_return['code'] != NO_ERROR:
            return create_slice_return

        # Now get the slice credential so it can be returned
        slice_urn = create_slice_return['value']['SLICE_URN']
        creds_return = sa.get_credentials(slice_urn, creds, {})
        if creds_return['code'] != NO_ERROR:
            return creds_return

        # Locate the SFA credential
        slice_cred = None
        for cred in creds_return['value']:
            if cred['geni_type'] == 'geni_sfa':
                slice_cred = cred['geni_value']
                break
        if slice_cred is None:
            # No SFA credential found!
            return self._errorReturn('No slice credential available')
        return self._successReturn(slice_cred)

    def RenewSlice(self, client_cert, args):
        # args are credential, expiration
        # cred is user cred
        # returns renewed slice credential
        slice_credential = args['credential']
        expiration = args['expiration']

        cred = sfa.trust.credential.Credential(string=slice_credential)
        slice_gid = cred.get_gid_object()
        slice_urn = slice_gid.get_urn()

        # Renew via update_slice in SA
        credentials = [slice_credential]
        if isinstance(slice_credential, str) or isinstance(slice_credential, unicode):
            credentials = [{'geni_type': 'SFA', 'geni_value': slice_credential}] 
        options = {'fields' : {'SLICE_EXPIRATION' : expiration}}
        sa = self._sa_handler
        update_slice_return = sa.update_slice(slice_urn,
                                              credentials, options)
        if update_slice_return['code'] != NO_ERROR:
            return update_slice_return

        creds_return = sa.get_credentials(slice_urn,
                                          credentials, {})
        if creds_return['code'] != NO_ERROR:
            return creds_return

        # Locate the SFA credential
        slice_cred = None
        for cred in creds_return['value']:
            if cred['geni_type'] == 'geni_sfa':
                slice_cred = cred['geni_value']
                break
        if slice_cred is None:
            # No SFA credential found!
            return self._errorReturn('No slice credential available')
        return self._successReturn(slice_cred)

    def GetKeys(self, client_cert, args):
        # cred is user cred
        # return list( of dict(type='ssh', key=$key))
        # args: credential

        self.logger.info("Called GetKeys")

        credential = args['credential']
        creds = [credential]
        # FIXME: SFA or geni_sfa?
        if isinstance(credential, str) or isinstance(credential, unicode):
            creds = [{'geni_type': 'SFA', 'geni_value': credential}] 

        member_urn = get_urn_from_cert(client_cert)

        options = {'match' : {'KEY_MEMBER' : member_urn},
                   "filter" : ['KEY_PUBLIC']
                   }
        ssh_keys_result = \
            self._ma_handler.lookup_keys(creds, options)
#        print "SSH_KEYS_RESULT = " + str(ssh_keys_result)
        if ssh_keys_result['code'] != NO_ERROR:
            return ssh_keys_result

        ssh_keys_value = ssh_keys_result['value']
        if not ssh_keys_value or \
                not ssh_keys_value.has_key(member_urn):
            user_email = get_email_from_cert(client_cert)
            msg = "GetKeys: No entry for member %s from lookup_keys" % member_urn
            chapi_warn(PGCH_LOG_PREFIX, msg, {'user': user_email})
            raise CHAPIv1ServerError(msg)

        keys = [{'type' : 'ssh' , 'key' : ssh_key['KEY_PUBLIC']} \
                    for ssh_key in ssh_keys_value[member_urn]]
        
        return self._successReturn(keys)

    def ListComponents(self, client_cert, args):
        """Get the list of CMs (AMs).

        Return a list of dicts. Each dict has keys gid, urn, hrn, url.
        """
        self.logger.info("Called ListComponents")
        filter = ['SERVICE_CERT', 'SERVICE_URN', 'SERVICE_URL']
        options = dict(filter=filter)
        get_aggregates_result = self._ch_handler.lookup_aggregates(options)
        if get_aggregates_result['code'] != NO_ERROR:
            return get_aggregates_result
        aggregates = get_aggregates_result['value']
        components = []
        for aggregate in aggregates:
            gid_file = aggregate['SERVICE_CERT']
            urn = aggregate['SERVICE_URN']
            url = aggregate['SERVICE_URL']
            sfa_hrn,sfa_type = sfa.util.xrn.urn_to_hrn(urn)
            # Clean up the HRN
            hrn = sfa_hrn.replace('\\', '')
            # Load the certificate from file
            try:
                with open(gid_file, 'r') as f:
                    gid = f.read()
            except:
                msg = 'ListComponents: gid file %r cannot be read.'
                msg = msg % (gid_file)
                user_email = get_email_from_cert(client_cert)
                chapi_error(PGCH_LOG_PREFIX, msg, {'user': user_email})
                gid = ''
            component = {'gid' : gid, 'urn' : urn, 'hrn' : hrn, 'url' : url}
            components.append(component)
        return self._successReturn(components)
