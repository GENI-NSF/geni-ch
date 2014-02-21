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

import optparse
import os, sys
import sfa.trust.certificate
import sfa.trust.gid
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

    # If no speaking_for option, this is not speaks-for. Return the
    # cert and options as given
    if not speaking_for:
        return client_cert, options

    # Pull out speaks_for credential
    # Caution -- what if more than one speaks_for credential? Continue
    # to hunt until we find the right one?
    speaks_for_credential = None
    for credential in credentials:
        if credential['geni_type'] == 'geni_abac' and \
                credential['geni_value'].find('speaks_for') >= 0:
            speaks_for_credential = credential['geni_value']
            break

    client_urn = get_urn_from_cert(client_cert)
    # If there is a speaking_for option but no speaks-for credential, error.
    if speaking_for and not speaks_for_credential:
        msg = "No speaks-for credential but %r passed option speaking_for = %r"
        msg = msg % (client_urn, speaking_for)
        chapi_error('SPEAKSFOR', msg)
        raise CHAPIv1AuthorizationError("Missing speaks-for credential.")

    # We are processing a speaks-for request

    # Get the agent_cert (the actor being spoken for)
    agent_cert = get_cert_from_credential(speaks_for_credential)

    # Need to validate the agent_cert against the trust roots
    if trusted_roots:
        agent_gid = sfa.trust.gid.GID(string=agent_cert)
        try :
            agent_gid.verify_chain(trusted_roots)
        except Exception, e:
            raise Exception("Agent certifiate no trusted")

    # Get the agent_urn (of the actor being spoken for)
    agent_urn = get_urn_from_cert(agent_cert)
    
    # The agent_urn must match the speaking_for option
    if agent_urn != speaking_for:
        msg = "Mismatch: speaking_for %s and agent URN %s"
        msg = msg % (speaking_for, agent_urn)
        chapi_error('SPEAKSFOR', msg)
        raise CHAPIv1AuthorizationError(msg)

    # The speaks-for credential must assert the statement 
    # AGENT.speaks_for(AGENT)<-CLIENT
    query = "AGENT.speaks_for(AGENT)<-CLIENT"
    certs_by_name = {"CLIENT" : client_cert, "AGENT" : agent_cert}

    # Run the proof in a separate process to avoid memory issues
    ok, proof = execute_abac_query(query, certs_by_name,
                                   [speaks_for_credential])
    if not ok:
        msg = ("Speaks-For credential does not assert that agent %s"
               + " allows client %s to speak for agent")
        msg = msg % (agent_urn, client_urn)
        chapi_error('SPEAKSFOR', msg)
        raise CHAPIv1AuthorizationError(msg)

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

    parser.add_option("--speaks_for_cred", \
                          help="Location of speaks-for credential", \
                          default=None)
    parser.add_option("--speaker_cert", help="Location of speaker cert", \
                          default=os.path.join(gcf_home, 'alice-cert.pem'))
    parser.add_option("--agent_cert", help="Location of spoken-for cert", \
                          default=None)
    parser.add_option("--agent_urn", help="URN of (spoken-for) agent", \
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
        credentials.append({'geni_type' : 'ABAC', 'geni_value' : sf_cred, 'geni_version' : '1'})

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
            print "Speaking for: Client = %s Agent = %s Options = %s" \
                % (client_urn, agent_urn, options)
    except Exception as e:
        print "Error: " + str(e)

                      
