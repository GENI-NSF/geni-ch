#!/bin/bash
#
# Unit tests for CH server functionality
# Assumes test server is running on https://localhost:9999

HOME=`pwd`
CHAPIDIR=$HOME
#ls -l /usr/share/geni-ch/CA
#ls -l /usr/share/geni-ch/ma
#ls -l /usr/share/geni-ch/sa

# set -x
 
# Function to invoke client.py and save output in given file
# pull single value from result and compare with expected result
# Usage: invoke_client user_prefix server method outfile 
#         match expected [optional_argument]
function invoke_client {
    local user_prefix=$1
    local server=$2
    local method=$3
    local outfile=$4
    local match=$5
    local expected=$6
    local additional=$7
    python $CHAPIDIR/tools/client.py --method $method \
	--url https://localhost:9999/$server \
	--key $user_prefix-key.pem --cert $user_prefix-cert.pem \
        $7 --raw_output > $outfile
    RESULT=`python $CHAPIDIR/tools/json_extractor.py $match $outfile`

    if [ $RESULT != $6 ]; then
	echo "Expected $6, got $RESULT: METHOD $method, SERVER $server, USER $user_prefix"
        exit 1
    else
	echo "Match $RESULT: METHOD $method, SERVER $server, USER $user_prefix"
    fi
}

# Test the "no authentication" methods
invoke_client /usr/share/geni-ch/ma/ma MA get_version /tmp/ma_get_version.out \
    value,CREDENTIAL_TYPES,version=3,type geni_sfa
invoke_client /usr/share/geni-ch/sa/sa SA get_version /tmp/sa_get_version.out \
    value,CREDENTIAL_TYPES,version=3,type geni_sfa
invoke_client /usr/share/geni-ch/ma/ma SR get_version /tmp/sr_get_version.out \
    value,API_VERSIONS,2 https://127.0.0.1:9999/SR
invoke_client /usr/share/geni-ch/ma/ma SR get_services \
    /tmp/sr_get_services.out value,SERVICE_TYPE=2,SERVICE_URN \
    urn:publicid:IDN+chtest+authority+sa

cat /tmp/test_server.log 
cat /tmp/chapi.log

# Create a first user, priv
PRIV_URN=urn:publicid:IDN+chtest+user+priv
PRIV_EPPN=priv@geni.net
invoke_client /usr/share/geni-ch/ma/ma MA create_member /tmp/priv-raw.json \
    value,name=urn,value $PRIV_URN --string_arg=$PRIV_EPPN
invoke_client /usr/share/geni-ch/ma/ma MA create_certificate \
    /tmp/create_cert.out code 0 --urn=$PRIV_URN
printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $PRIV_EPPN \
    > /tmp/lookup_priv.json

invoke_client /usr/share/geni-ch/ma/ma MA lookup_login_info \
    /tmp/lookup_priv.json \
    code 0 --options_file=/tmp/lookup_priv.json
cat /tmp/lookup_priv.json
python $CHAPIDIR/tools/json_extractor.py \
    value,urn:$PRIV_URN,_GENI_MEMBER_SSL_PRIVATE_KEY  \
    /tmp/lookup_priv.json > /tmp/priv-key.pem
cat /tmp/priv-key.pem

python $CHAPIDIR/tools/json_extractor.py \
    value,urn:$PRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  \
    /tmp/lookup_priv.json > /tmp/priv-cert.pem
cat /tmp/priv-cert.pem

# Create a second user, unpriv

UNPRIV_URN=urn:publicid:IDN+chtest+user+unpriv
UNPRIV_EPPN=unpriv@geni.net
invoke_client /usr/share/geni-ch/ma/ma MA create_member /tmp/unpriv-raw.json \
    value,name=urn,value $UNPRIV_URN --string_arg=$UNPRIV_EPPN
invoke_client /usr/share/geni-ch/ma/ma MA create_certificate \
    /tmp/create_cert.out code 0 --urn=$UNPRIV_URN
printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $UNPRIV_EPPN \
    > /tmp/lookup_unpriv.json


invoke_client /usr/share/geni-ch/ma/ma MA lookup_login_info \
    /tmp/lookup_unpriv.json \
    code 0 --options_file=/tmp/lookup_unpriv.json
cat /tmp/lookup_unpriv.json
python $CHAPIDIR/tools/json_extractor.py \
    value,urn:$UNPRIV_URN,_GENI_MEMBER_SSL_UNPRIVATE_KEY  \
    /tmp/lookup_unpriv.json > /tmp/unpriv-key.pem
cat /tmp/unpriv-key.pem

python $CHAPIDIR/tools/json_extractor.py \
    value,urn:$UNPRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  \
    /tmp/lookup_unpriv.json > /tmp/unpriv-cert.pem
cat /tmp/unpriv-cert.pem

# From here...
# MA grants priv PI privileges
# priv succeeds to create a project
# priv succeeds to create a slice in project
# unpriv fails to create a project
# unpriv fails to create a slice in project
# unpriv fails to ask for members of given project
# unpriv fails to ask for members of given slice
# priv adds unpriv to the project
# unpriv succeeds to create a slice in project
# unpriv succeeds to ask for members of given project
# unpriv succeeds to ask for members of given slice

