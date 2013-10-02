#!/bin/bash
# Delete any reference to a project of given project_id 
# in LOGGING, CS, SA, PA data
#
# Usage: delete_project.sh project_id 

if [ $# -lt 1 ]; then
    echo "Usage: delete_project.sh project_id"
    exit
else
    PROJECT_ID=$1
    echo "delete from sa_slice_member where slice_id in (select slice_id from sa_slice where project_id = '$PROJECT_ID')" | psql -U portal -h localhost portal
    echo "delete from sa_slice where project_id = '$PROJECT_ID'" | psql -U portal -h localhost portal
    echo "delete from pa_project_member where project_id='$PROJECT_ID'" | psql -U portal -h localhost portal
    echo "delete from pa_project where project_id = '$PROJECT_ID'" | psql -U portal -h localhost portal
    echo "delete from logging_entry where id in (select event_id from logging_entry_attribute where attribute_name = 'PROJECT' and attribute_value = '$PROJECT_ID')" | psql -U portal -h localhost portal
    echo "delete from logging_entry_attribute where attribute_name = 'PROJECT' and attribute_value = '$PROJECT_ID'" | psql -U portal -h localhost portal
    echo "delete from cs_assertion where context_type = 1 and context = '$PROJECT_ID'" | psql -U portal -h localhost portal
fi




