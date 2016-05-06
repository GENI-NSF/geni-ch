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

import optparse
import os, sys
import gcf.sfa.trust.certificate
import gcf.sfa.trust.credential
import gcf.sfa.trust.credential_factory
import gcf.sfa.trust.gid
import chapi_log
from cert_utils import *
from ABACManager import *
from chapi.Exceptions import *


# Determine if the given method context is 'speaks-for'
# That is:
#     1. There is a 'speaking_for' option with the value of the
#          URN of the spoken-for user
#     2. There is a speaks-for credential in the list of credentials
#         that is signed by the spoken-for user authorizing the
#         speaking entity to speak for it
#     3. The URN of the 'speaking_for' option matches the URN
#         in the speaks-for credential
#     4. The certificate of the spoken-for user is in the
#         list of credentials [Note: This one is still open to debate...]
#
# Args:
#   client_cert: the cert of the actual invoker of the SSL connection
#   credentials: the list of credentials passed with the call,
#        possibly including user certs and speaks-for credentials
#   options: the dictionary of options supplied with the call,
#        possibly including a 'speaking_for' option
#
# Return:
#   agent_cert: Cert of actual (spoken for) speaker if 'speaks for',
#        client_cert if not.
#   revised_options : Original options with
#       {'speaking_as' : original_client_cert} added if 'speaks for'
def determine_speaks_for(client_cert, credentials, options, trusted_roots=None):

    # Pull out speaking_for option
    OPTION_SPEAKING_FOR = 'speaking_for'
    speaking_for = None
    if options.has_key(OPTION_SPEAKING_FOR):
        speaking_for = options[OPTION_SPEAKING_FOR]

    # Grab client URN out of client cert
    client_urn = get_urn_from_cert(client_cert)

    # If no speaking_for option, this is not speaks-for. Return the
    # cert and options as given
    if not speaking_for:
        if trusted_roots:
            client_gid = gcf.sfa.trust.gid.GID(string=client_cert)
            try :
                client_gid.verify_chain(trusted_roots)
            except Exception, e:
                chapi_info("SPEAKSFOR", "Client %s: certificate not trusted"
                           % (client_urn))
                msg = "Client %s is not authorized to make API calls."
                raise CHAPIv1AuthorizationError(msg % (client_urn))
            return client_cert, options
        else:
            # This is probably a configuration error. There should
            # always be trusted roots.
            chapi_warn("SPEAKSFOR",
                       "No trusted roots in determine_speaks_for.")
            return client_cert, options

    # Loop over all ABAC credentials and see if any prove
    # AGENT.speaks_for(AGENT)<-CLIENT
    speaks_for_found = False
    for sf_credential in credentials:
        if sf_credential['geni_type'] != 'geni_abac': continue
        sf_cred_value = sf_credential['geni_value']
        agent_cert = get_cert_from_credential(sf_cred_value)
        agent_urn = get_urn_from_cert(agent_cert)

        # Need to validate the agent_cert against the trust roots
        if trusted_roots:
            agent_gid = gcf.sfa.trust.gid.GID(string=agent_cert)
            try :
                agent_gid.verify_chain(trusted_roots)
            except Exception, e:
                chapi_info("SPEAKSFOR", "Agent certificate not trusted %s"
                           % (agent_urn))

        # The agent_urn must match the speaking_for option
        if agent_urn != speaking_for:
            continue

        # See if the credential asserts the right speaks_for statement
        query = "AGENT.speaks_for(AGENT)<-CLIENT"
        certs_by_name = {"CLIENT" : client_cert, "AGENT" : agent_cert}
        ok, proof = execute_abac_query(query, certs_by_name,
                                       [sf_cred_value])
        if ok:
            speaks_for_found = True
            break

    # If we didn't found a speaks-for credential, raise error
    if not speaks_for_found:
        # If there is a speaking_for option but no
        # speaks-for credential, error.
        msg = "No speaks-for credential but %r passed option speaking_for = %r"
        msg = msg % (client_urn, speaking_for)
        chapi_error('SPEAKSFOR', msg)
        msg = "Missing credential allowing %s to speak-for  %s."
        raise CHAPIv1AuthorizationError(msg % (client_urn, speaking_for))

    # Success: add the speaking_as option and return the agent_cert
    msg = "%r is speaking for %r" % (client_urn, agent_urn)
    chapi_info('SPEAKSFOR', msg)

    # Make a copy of original options
    revised_options = dict(options)
    # Update options
    revised_options['speaking_as'] = client_urn

    return agent_cert, revised_options


def parseOptions():
    parser = optparse.OptionParser()

    home = os.getenv('HOME')
    gcf_home = os.path.join(home, '.gcf')

    parser.add_option("--speaks_for_cred",
                          help="Location of speaks-for credential",
                          default=None)
    parser.add_option("--speaker_cert", help="Location of speaker cert",
                          default=os.path.join(gcf_home, 'alice-cert.pem'))
    parser.add_option("--agent_cert", help="Location of spoken-for cert",
                          default=None)
    parser.add_option("--agent_urn", help="URN of (spoken-for) agent",
                          default=None)

    [opts, args] = parser.parse_args(sys.argv)
    return opts, args


if __name__ == "__main__":

    opts, args = parseOptions()

    options = {}
    client_cert = open(opts.speaker_cert).read()
    credentials = []
    if opts.speaks_for_cred:
        filename = opts.speaks_for_cred
        sf_cred = open(filename).read()
        credentials.append({'geni_type' : 'ABAC',
                            'geni_value' : sf_cred,
                            'geni_version' : '1'})

    # Set agent_urn
    agent_urn = None
    if opts.agent_urn:
        agent_urn = opts.agent_urn
    if opts.agent_cert:
        agent_cert = open(opts.agent_cert).read()
        agent_urn = get_urn_from_cert(agent_cert)

    if agent_urn:
        options['speaking_for'] = agent_urn

    try:
        agent_cert, revised_options = \
            determine_speaks_for(client_cert, credentials, options)
        agent_urn = get_urn_from_cert(agent_cert)
        client_urn = get_urn_from_cert(client_cert)
        if agent_cert == client_cert:
            print "Direct (not speaks-for): Agent = %s" % agent_urn
        else:
            print ("Speaking for: Client = %s Agent = %s Options = %s"
                   % (client_urn, agent_urn, options))
    except Exception as e:
        print "Error: " + str(e)
