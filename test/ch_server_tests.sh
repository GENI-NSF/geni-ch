#!/bin/bash
#
# Unit tests for CH server functionality
# Assumes test server is running on https://localhost:9999

HOME=`pwd`
CHAPIDIR=$HOME
TESTCOUNT=0
DATADIR=/usr/share/geni-ch
MADIR=$DATADIR/ma
SADIR=$DATADIR/sa
CH_URL=https://localhost:9999

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
    local comment=$8
    python $CHAPIDIR/tools/client.py --method $method \
	--url $CH_URL/$server \
	--key $user_prefix-key.pem --cert $user_prefix-cert.pem \
        $7 --raw_output > $outfile
    RESULT=`python $CHAPIDIR/tools/json_extractor.py $match $outfile`

    if [ $RESULT != $6 ]; then
	echo "Test $TESTCOUNT: Expected $6, got $RESULT: METHOD $method, SERVER $server, USER $user_prefix"
        exit 1
    else
	echo "Test $TESTCOUNT: $server.$method succeeded ($comment)"
    fi

    TESTCOUNT=$((TESTCOUNT+1))
}

# Wait for the server to start up
sleep 5

# Test the "no authentication" methods
invoke_client $MADIR/ma MA get_version /tmp/ma_get_version.out \
    value,CREDENTIAL_TYPES,version=3,type geni_sfa
#cat /tmp/ma_get_version.out
invoke_client $SADIR/sa SA get_version /tmp/sa_get_version.out \
    value,CREDENTIAL_TYPES,version=3,type geni_sfa
#cat /tmp/sa_get_version.out
invoke_client $MADIR/ma SR get_version /tmp/sr_get_version.out \
    value,API_VERSIONS,2 https://127.0.0.1:9999/SR
invoke_client $MADIR/ma SR get_services \
    /tmp/sr_get_services.out value,SERVICE_TYPE=2,SERVICE_URN \
    urn:publicid:IDN+chtest+authority+sa

#cat /tmp/test_server.log 

# Create a first user, priv
PRIV_URN=urn:publicid:IDN+chtest+user+priv
PRIV_EPPN=priv@geni.net
invoke_client $MADIR/ma MA create_member /tmp/priv-raw.json \
    value,name=urn,value $PRIV_URN --string_arg=$PRIV_EPPN
#cat /tmp/priv-raw.json
PRIV_UID=`python $CHAPIDIR/tools/json_extractor.py value,value=$PRIV_URN,member_id /tmp/priv-raw.json`
#echo $PRIV_UID
invoke_client $MADIR/ma MA create_certificate \
    /tmp/create_cert.out code 0 --urn=$PRIV_URN
printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $PRIV_EPPN \
    > /tmp/lookup_opts_priv.json

invoke_client $MADIR/ma MA lookup_login_info \
    /tmp/lookup_lli_priv.json \
    code 0 --options_file=/tmp/lookup_opts_priv.json
python $CHAPIDIR/tools/json_extractor.py \
    value,$PRIV_URN,_GENI_MEMBER_SSL_PRIVATE_KEY  \
    /tmp/lookup_lli_priv.json > /tmp/priv-key.pem
#cat /tmp/priv-key.pem

python $CHAPIDIR/tools/json_extractor.py \
    value,$PRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  \
    /tmp/lookup_lli_priv.json > /tmp/priv-cert.pem
#cat /tmp/priv-cert.pem

# Create a second user, unpriv

UNPRIV_URN=urn:publicid:IDN+chtest+user+unpriv
UNPRIV_EPPN=unpriv@geni.net
invoke_client $MADIR/ma MA create_member /tmp/unpriv-raw.json \
    value,name=urn,value $UNPRIV_URN --string_arg=$UNPRIV_EPPN
UNPRIV_UID=`python $CHAPIDIR/tools/json_extractor.py value,value=$UNPRIV_URN,member_id /tmp/unpriv-raw.json`
#echo $UNPRIV_UID
invoke_client $MADIR/ma MA create_certificate \
    /tmp/create_cert.out code 0 --urn=$UNPRIV_URN 
printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $UNPRIV_EPPN \
    > /tmp/lookup_opts_unpriv.json

invoke_client $MADIR/ma MA lookup_login_info \
    /tmp/lookup_lli_unpriv.json \
    code 0 --options_file=/tmp/lookup_opts_unpriv.json
python $CHAPIDIR/tools/json_extractor.py \
    value,$UNPRIV_URN,_GENI_MEMBER_SSL_PRIVATE_KEY  \
    /tmp/lookup_lli_unpriv.json > /tmp/unpriv-key.pem
#cat /tmp/unpriv-key.pem

python $CHAPIDIR/tools/json_extractor.py \
    value,$UNPRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  \
    /tmp/lookup_lli_unpriv.json > /tmp/unpriv-cert.pem
#cat /tmp/unpriv-cert.pem

# Grant priv PI privileges
$CHAPIDIR/bin/geni-add-member-privilege --keyfile=$MADIR/ma-key.pem \
    --certfile=$MADIR/ma-cert.pem --url=$CH_URL --member priv --lead > /dev/null

# Let priv create a project
PROJECT_NAME=testproj

printf "{\"fields\" : {\"PROJECT_DESCRIPTION\" : \"description\", \"PROJECT_NAME\" : \"$PROJECT_NAME\", \"_GENI_PROJECT_OWNER\" : \"$PRIV_UID\" }}" > /tmp/create_project_options.json
#cat /tmp/create_project_options.json
invoke_client /tmp/priv SA create_project /tmp/create_project.json \
    code 0 --options_file=/tmp/create_project_options.json
#cat /tmp/create_project.json
PROJECT_URN=`python $CHAPIDIR/tools/json_extractor.py value,PROJECT_URN /tmp/create_project.json`
#echo $PROJECT_URN

# Let priv create a slice in the project
SLICE_NAME=testslice
printf "{\"fields\" : {\"SLICE_DESCRIPTION\" : \"description\", \"SLICE_PROJECT_URN\" : \"$PROJECT_URN\", \"SLICE_NAME\" : \"$SLICE_NAME\" }}" > /tmp/create_slice_options.json
#cat /tmp/create_slice_options.json
invoke_client /tmp/priv SA create_slice /tmp/create_slice.json \
    code 0 --options_file=/tmp/create_slice_options.json
SLICE_URN=`python $CHAPIDIR/tools/json_extractor.py value,SLICE_URN /tmp/create_slice.json`
#echo $SLICE_URN

# Let unpriv try to create a project and fail
PROJECT2_NAME=testproj2

printf "{\"fields\" : {\"PROJECT_DESCRIPTION\" : \"description\", \"PROJECT_NAME\" : \"$PROJECT2_NAME\", \"_GENI_PROJECT_OWNER\" : \"$PRIV_UID\" }}" > /tmp/create_project_options.json
#cat /tmp/create_project_options.json
invoke_client /tmp/unpriv SA create_project /tmp/create_project.json \
    code 2 --options_file=/tmp/create_project_options.json "UNPRIV can't create project"
#cat /tmp/create_project.json

# Let unpriv try (and fail) to create a slice in the original project 
SLICE_NAME=testslice2
printf "{\"fields\" : {\"SLICE_DESCRIPTION\" : \"description\", \"SLICE_PROJECT_URN\" : \"$PROJECT_URN\", \"SLICE_NAME\" : \"$SLICE_NAME\" }}" > /tmp/create_slice_options.json
#cat /tmp/create_slice_options.json
invoke_client /tmp/unpriv SA create_slice /tmp/create_slice.json \
    code 2 --options_file=/tmp/create_slice_options.json "UNPRIV can't create slice in testproj"
#cat /tmp/create_slice.json

# Let unpriv try (and fail) to request members of testproj
printf  "{\"match\" : {\"PROJECT_URN\" : \"$PROJECT_URN\"}}" > /tmp/lookup_project_members.json
invoke_client /tmp/unpriv SA lookup_project_members /tmp/lookup_members.json \
    code 3 --options_file=/tmp/lookup_project_members.json "UNPRIV can't lookup_members for testproj"
cat /tmp/lookup_members.json

# Let unpriv try (and fail) to request members of testslice
printf  "{\"match\" : {\"SLICE_URN\" : \"$SLICE_URN\"}}" > /tmp/lookup_slice_members.json
invoke_client /tmp/unpriv SA lookup_slice_members /tmp/lookup_members.json \
    code 3 --options_file=/tmp/lookup_slice_members.json "UNPRIV can't lookup_members for testslice"
cat /tmp/lookup_members.json



# From here...
# priv adds unpriv to the project
# unpriv succeeds to create a slice in project
# unpriv succeeds to ask for members of given project
# unpriv succeeds to ask for members of given slice

