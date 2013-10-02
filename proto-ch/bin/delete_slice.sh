#!/bin/bash
# Delete any reference to a slice of given slice_id 
# in LOGGING, CS, SA data
#
# Usage: delete_slice.sh slice_id 

if [ $# -lt 1 ]; then
    echo "Usage: delete_slice.sh slice_id"
    exit
else
    SLICE_ID=$1
    echo "delete from sa_slice_member where slice_id='$SLICE_ID'" | psql -U portal -h localhost portal
    echo "delete from sa_slice where slice_id = '$SLICE_ID'" | psql -U portal -h localhost portal
    echo "delete from logging_entry where id in (select event_id from logging_entry_attribute where attribute_name = 'SLICE' and attribute_value = '$SLICE_ID')" | psql -U portal -h localhost portal
    echo "delete from logging_entry_attribute where attribute_name = 'SLICE' and attribute_value = '$SLICE_ID'" | psql -U portal -h localhost portal
    echo "delete from cs_assertion where context_type = 2 and context = '$SLICE_ID'" | psql -U portal -h localhost portal
fi




