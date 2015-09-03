#!/bin/bash
# Assert an email address for an eppn. For use when an IdP sends us
# the eppn but no the email address for a user, and the portal sends
# us email. From the email, the eppn is in the 'Subject' field and the
# email address is in the 'From' field.
# After running this script, reply to the email, asking them to try again.
#
# Usage: assert_email.sh <eppn> <email>

if [ $# -ne 2 ]; then
    echo "Usage: assert_email.sh <eppn> <email>"
    exit
else
    EPPN=$1
    EMAIL=$2
    USER=`whoami`

    ASSERTER=`psql -U portal -h localhost portal -q -t -c "select distinct member_id from ma_member_attribute where value = '$USER'"`
    ASSERTER=`echo $ASSERTER | tr -d ' '`
    if [ -z "$ASSERTER" ]; then
	echo "Could not find member_id for asserter for user $USER"
	exit
    fi

    echo "$USER asserting email $EMAIL for eppn $EPPN"
    echo
    res1=`echo "insert into km_asserted_attribute (eppn, name, value, asserter_id) select '$EPPN', 'mail', '$EMAIL', '$ASSERTER' where not exists (select 1 from km_asserted_attribute where name='mail' and eppn='$EPPN')" | psql -U portal -h localhost portal`
    res=`echo $res1 | tr -d ' '`
    if [ "$res" = "INSERT01" ]; then
	echo "1 row inserted"
    elif [ "$res" = "INSERT00" ]; then
	res2=`echo "select value || ', asserted by: ' || asserter_id from km_asserted_attribute where name='mail' and eppn='$EPPN'" | psql -U portal -h localhost portal -q -t`
	echo " ** EPPN $EPPN already has email:$res2"
    else
	echo " ** Unknown error: $res1"
    fi
fi