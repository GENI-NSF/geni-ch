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

    echo "insert into cs_assertion (principal, attribute, context_type, context)" > $FILENAME
    echo "select account.account_id, cs_attribute.id, cs_context_type.id, null " >> $FILENAME
    echo " from account, cs_context_type, cs_attribute " >> $FILENAME
    echo " where username = '$PERSON' " >> $FILENAME
    echo " and lower(cs_context_type.name) = lower('$CONTEXT_TYPE')" >> $FILENAME
    echo " and lower(cs_attribute.name) = lower('$ATTRIBUTE')" >> $FILENAME
else 
    if [ "$CONTEXT_TYPE" == "project" ]; then
#      PROJECT 
	PROJECT_ID=$4
	echo "insert into cs_assertion (principal, attribute, context_type, context)" > $FILENAME
	echo "select account.account_id, cs_attribute.id, 1, pa_project.project_id " >> $FILENAME
	echo " from account, pa_project, cs_attribute  " >> $FILENAME
	echo " where username = '$PERSON' AND project_name = '$PROJECT_ID'" >> $FILENAME
	echo " and lower(cs_attribute.name) = lower('$ATTRIBUTE')" >> $FILENAME
    elif [ "$CONTEXT_TYPE" == "slice" ]; then
#      SLICE 
	SLICE_ID=$4
	echo "insert into cs_assertion (principal, attribute, context_type, context)" > $FILENAME
	echo "select account.account_id, cs_attribute.id, 2, sa_slice.slice_id " >> $FILENAME
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
