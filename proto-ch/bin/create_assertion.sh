#!/bin/bash

# Assert attribute for a person
# Usage create_assertion.sh person_name, attribute, context_type, [context_id]
# Attribute: lead, admin member auditor
# Context_Type: project, slice, resource, service member
# For context_type = project, must provide project name
# For context_type = slice, must provide slice name

if [ $# -lt 3 ]; then
    echo "Usage: create_assertion.sh person_name attribute context_type [context_id]"
    echo "Attribute: lead, admin, member, auditor"
    echo "Context_Type: project,  slice,  resource,  service,  member"
    echo "For context_type = project, must provide project name"
    echo "For context_type = slice, must provide slice name"
    exit
fi

PERSON=$1
ATTRIBUTE=$2
CONTEXT_TYPE=$3
FILENAME="/tmp/aa.$USER.sql";

if [ $# -eq 3 ]; then
    # No context for types 3 4 5
    if [[ $CONTEXT_TYPE == "slice" || $CONTEXT_TYPE == "project" ]]; then
	echo "Must provide slice name for slice context or project name for project context"
	exit
    fi
    

# account : account_id, status, username
# signer | principal | attribute | context_type | context 

    # downcase here
    CONTEXT_TYPE=${CONTEXT_TYPE,,}
    ATTRIBUTE=${ATTRIBUTE,,}

    # TODO: we really ought to drop rows that have prior values
    if [ "$ATTRIBUTE" == "operator" ]; then
	echo "insert into ma_member_attribute (member_id, name, value, self_asserted)" > $FILENAME
	echo "select account.account_id, 'OPERATOR', 'true', 'f' " >> $FILENAME
	echo " from account" >> $FILENAME
	echo " where username = '$PERSON' " >> $FILENAME
    else if [ "$CONTEXT_TYPE" == "project" && 
		( "$ATTRIBUTE" == "lead" || "$ATTRIBUTE" == "project_lead" ) ]; then
	echo "insert into ma_member_attribute (member_id, name, value, self_asserted)" > $FILENAME
	echo "select account.account_id, 'PROJECT_LEAD', 'true', 'f' " >> $FILENAME
	echo " from account" >> $FILENAME
	echo " where username = '$PERSON' " >> $FILENAME
    else
	echo "Only operator and project_lead supported for context-less assertions."
	exit
    fi
else 
    if [ "$CONTEXT_TYPE" == "project" ]; then
#      PROJECT 
	PROJECT_ID=$4
	echo "insert into pa_project_member (member_id, role, project_id)" > $FILENAME
	echo "select account.account_id, cs_attribute.id, pa_project.project_id " >> $FILENAME
	echo " from account, pa_project, cs_attribute  " >> $FILENAME
	echo " where username = '$PERSON' AND project_name = '$PROJECT_ID'" >> $FILENAME
	echo " and lower(cs_attribute.name) = lower('$ATTRIBUTE')" >> $FILENAME
    elif [ "$CONTEXT_TYPE" == "slice" ]; then
#      SLICE 
	SLICE_ID=$4
	echo "insert into sa_slice_member (member_id, role, slide_id)" > $FILENAME
	echo "select account.account_id, cs_attribute.id, sa_slice.slice_id " >> $FILENAME
	echo " from account, sa_slice, cs_attribute " >> $FILENAME
	echo " where username = '$PERSON' AND slice_name = '$SLICE_ID' " >> $FILENAME
	echo " and lower(cs_attribute.name) = lower('$ATTRIBUTE')" >> $FILENAME
    else
	echo "ILLEGAL CASE: No context for context_type $CONTEXT_TYPE";
	exit
    fi
fi


psql -U portal -h localhost < $FILENAME
rm $FILENAME
