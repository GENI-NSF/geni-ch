# Simple persistence-free version of MA for testing/development
from chapi.MemberAuthority import MAv1DelegateBase
from chapi.Exceptions import *
from ext.geni.util.urn_util import URN
from tools.dbutils import *
import ext.sfa.trust.credential as sfa_cred
import ext.sfa.trust.gid as sfa_gid

class MAv1Implementation(MAv1DelegateBase):

    version_number = "1.0"
    credential_types = ["SFA", "ABAC"]
    fields = {
        "MEMBER_DISPLAYNAME": {"TYPE": "STRING", "CREATE": "ALLOWED", "UPDATE": True, "PROTECT": "IDENTIFYING"},
        "MEMBER_AFFILIATION": {"TYPE": "STRING", "CREATE": "ALLOWED", "UPDATE": True, "PROTECT": "IDENTIFTYING"},
        "MEMBER_SPEAKS_FOR_CREDENTIAL": {"TYPE": "CREDENTIAL"},
        "MEMBER_SSL_PUBLIC_KEY": {"TYPE": "SSL_KEY"},
        "MEMBER_SSL_PRIVATE_KEY": {"TYPE": "SSL_KEY", "PROTECT": "PRIVATE"},
        "MEMBER_SSH_PUBLIC_KEY": {"TYPE": "SSH_KEY"},
        "MEMBER_SSH_PRIVATE_KEY": {"TYPE": "SSH_KEY", "PROTECT": "PRIVATE"},
        "MEMBER_ENABLED": {"TYPE": "BOOLEAN", "UPDATE": True},
        "USER_CREDENTIAL": {"TYPE": "CREDENTIAL"}
	}

    # This call is unprotected: no checking of credentials
    def get_version(self):
        version_info = {"VERSION": self.version_number,
                        "CREDENTIAL_TYPES": self.credential_types,
                        "FIELDS": self.fields}
        return self._successReturn(version_info)

    # This call is unprotected: no checking of credentials
    def lookup_public_member_info(self, credentials, options):
        print "MAv1DelegateBase.lookup_public_member_info " + \
            "CREDS = %s OPTIONS = %s" % \
            (str(credentials), str(options))
        if not options.get('match'):
            raise CHAPIv1ArgumentError('Missing a "match" option')
        if not options['match'].get('MEMBER_URN'):
            raise CHAPIv1ArgumentError('Missing a "MEMBER_URN" in match option')
        if not options.get('filter'):
            raise CHAPIv1ArgumentError('Missing a "filter" option')
        if 'USER_CREDENTIAL' not in options['filter']:
            raise CHAPIv1ArgumentError('Missing a "USER_CREDENTIAL" in filter option')
        cred = sfa_cred.Credential()
        urn = options['match']['MEMBER_URN']
        print 'urn =', urn
        gid = sfa_gid.GID(urn=urn, create=True)
        print 'gid =', gid
        cred.set_gid_object(gid)
        cred.set_gid_caller(gid)
        print 'str =', cred.save_to_string()
        return cred.save_to_string()

    # This call is protected
    def lookup_private_member_info(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def lookup_identifying_member_info(self, client_cert, credentials, options):
        raise CHAPIv1NotImplementedError('')

    # This call is protected
    def update_member_info(self, client_cert, member_urn, credentials, options):
        raise CHAPIv1NotImplementedError('')
