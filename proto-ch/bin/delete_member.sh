#!/bin/bash
# Delete any reference to an account of a given member by member_id
# If second argument ('data_only') is set to non-zero,
#  only delete  CS, PA, SA and LOGGING data but not MA data
# If second argument ('data_only') is zero, delete MA data as well
#
# Usage: delete_member.sh member_id [data_only=1]

if [ $# -lt 1 ]; then
    echo "Usage: delete_member.sh member_id [data_only=1]"
    exit
else
    MEMBER_ID=$1
    DATA_ONLY=1;
    if [ $# -gt 1 ]; then
	DATA_ONLY=$2;
    fi
    if [ $DATA_ONLY -eq 0 ]; then
	echo "delete from ma_member_attribute where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
	echo "delete from ma_member_privilege where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
	echo "delete from ma_inside_key where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
	echo "delete from ma_ssh_key where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
	echo "delete from ma_member where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
    fi
    echo "delete from pa_project_member where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
    echo "delete from sa_slice_member where member_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
    echo "delete from logging_entry_attribute where event_id in (select id from logging_entry where user_id = '$MEMBER_ID')" | psql -U portal -h localhost portal
    echo "delete from logging_entry where user_id = '$MEMBER_ID'" | psql -U portal -h localhost portal
fi
