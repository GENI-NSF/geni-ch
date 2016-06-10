#!/bin/bash
#
# Unit tests for CH server functionality
# Assumes test server is running on https://localhost:9999

# Things to try
# Are we connecting to the database?
# set -e
# Look at the log after failure

set -x

# Set up environment
HOSTNAME=`hostname -f`
DATADIR=/usr/share/geni-ch
HOME=`pwd`
CHAPIDIR=$HOME

netstat -an | grep 9999
ps auxw | grep test
cat /tmp/test_server.log
 
curl -v -k --cert /usr/share/geni-ch/ma/ma-cert.pem --key /usr/share/geni-ch/ma/ma-key.pem -X POST -H "Content-Type: application/xml" -d "<?xml version=\"1.0\"?><methodCall><methodName>get_version</methodName><params></params></methodCall>" https://localhost:9999/SA

export PYTHONPATH=$PYTHONPATH:$CHAPIDIR
echo "PYTHONPATH = $PYTHONPATH"

python $CHAPIDIR/tools/client.py --method get_version --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --raw_output 

python $CHAPIDIR/tools/client.py --method get_version --url https://localhost:9999/SA --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --raw_output 

python $CHAPIDIR/tools/client.py --method get_version --url https://localhost:9999/SR --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --raw_output 

python $CHAPIDIR/tools/client.py --method get_services --url https://localhost:9999/SR --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --raw_output 

echo "{\"match\" : {}}" > /tmp/foo.json
python $CHAPIDIR/tools/client.py --method lookup_public_member_info --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --raw_output --options_file /tmp/foo.json

sudo service postfix status
postconf



#    Make a first user, priv
PRIV_EPPN=priv@geni.net
python $CHAPIDIR/tools/client.py --method create_member --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --string_arg=$PRIV_EPPN --raw_output > /tmp/priv-raw.json
cat /tmp/priv-raw.json
cat /tmp/test_server.log 

PRIV_URN=`python $CHAPIDIR/tools/json_extractor.py value,name=urn,value /tmp/priv-raw.json`

python $CHAPIDIR/tools/client.py --method create_certificate --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem  --cert /usr/share/geni-ch/ma/ma-cert.pem --urn $PRIV_URN

printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $PRIV_EPPN > /tmp/lookup_priv.json
cat /tmp/lookup_priv.json

# Grab certs and keys
python $CHAPIDIR/tools/client.py --method lookup_login_info --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.python $CHAPIDIR/tools/client.py --method lookup_login_info --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem  --cert /usr/share/geni-ch/ma/ma-cert.pem --options_file /tmp/lookup_priv.json --raw_output > /tmp/priv.json
cat /tmp/priv.json

python $CHAPIDIR/tools/json_extractor.py   value,urn:$PRIV_URN,_GENI_MEMBER_SSL_PRIVATE_KEY  /tmp/priv.json > /tmp/priv-key.pem
cat /tmp/priv-key.pem

python $CHAPIDIR/tools/json_extractor.py   value,urn:$PRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  /tmp/priv.json > /tmp/priv-cert.pem
cat /tmp/priv-cert.pem

# Make a second user, unpriv
UNPRIV_EPPN=unpriv3@geni.net
python $CHAPIDIR/tools/client.py --method create_member --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem --cert /usr/share/geni-ch/ma/ma-cert.pem --string_arg=$UNPRIV_EPPN --raw_output > /tmp/unpriv-raw.json
cat /tmp/unpriv-raw.json
UNPRIV_URN=`python $CHAPIDIR/tools/json_extractor.py value,name=urn,value /tmp/unpriv-raw.json`

python $CHAPIDIR/tools/client.py --method create_certificate --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem  --cert /usr/share/geni-ch/ma/ma-cert.pem --urn $UNPRIV_URN

printf "{\"match\" : {\"_GENI_MEMBER_EPPN\" : \"%s\"}}\n" $UNPRIV_EPPN > /tmp/lookup_unpriv.json
cat /tmp/lookup_unpriv.json

# Grab certs and keys
python $CHAPIDIR/tools/client.py --method lookup_login_info --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.python $CHAPIDIR/tools/client.py --method lookup_login_info --url https://localhost:9999/MA --key /usr/share/geni-ch/ma/ma-key.pem  --cert /usr/share/geni-ch/ma/ma-cert.pem --options_file /tmp/lookup_unpriv.json --raw_output > /tmp/unpriv.json
cat /tmp/unpriv.json

python $CHAPIDIR/tools/json_extractor.py   value,$UNPRIV_URN,_GENI_MEMBER_SSL_PRIVATE_KEY  /tmp/unpriv.json > /tmp/unpriv-key.pem
cat /tmp/unpriv-key.pem

python $CHAPIDIR/tools/json_extractor.py   value,$UNPRIV_URN,_GENI_MEMBER_SSL_CERTIFICATE  /tmp/unpriv.json > /tmp/unpriv-cert.pem
cat /tmp/unpriv-cert.pem




#    Set up test scripts, run each and compare with expected output


#  At the end, kill the server
jobs
ps auxw | grep python



