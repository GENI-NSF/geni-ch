#!/bin/bash

# List privileges for given user
# Usage: list_privileges.sh username

if [ $# -lt 1 ]; then
    echo "Usage: list_privileges.sh person_name"
exit
fi

PERSON=$1
FILENAME="/tmp/lp.$USER.sql";

# CS_POLICY : attribute, context_type, privilege
# CS_PRIVILEGE : ID, NAME
# CS_ACTION : ID, NAME, PRIVILEGE, CONTEXT_TYPE

# List privileges with no context
echo "Context-free Privileges:"
echo "select ma_member_attribute.value, cs_attribute.name, cs_action.name " > $FILENAME
echo " from ma_member_attribute, cs_attribute, cs_context_type, cs_assertion, cs_action, cs_policy " >> $FILENAME
echo " where ma_member_attribute.value = '$PERSON'" >> $FILENAME
echo " and ma_member_attribute.name = 'username'" >> $FILENAME
echo " and ma_member_attribute.member_id = cs_assertion.principal " >> $FILENAME
echo " and cs_attribute.id = cs_assertion.attribute " >> $FILENAME
echo " and cs_context_type.id = cs_assertion.context_type" >> $FILENAME
echo " and cs_assertion.context_type > 2" >> $FILENAME
echo " and cs_policy.attribute = cs_assertion.attribute" >> $FILENAME
echo " and cs_policy.context_type = cs_assertion.context_type" >> $FILENAME
echo " and cs_policy.privilege = cs_action.privilege" >> $FILENAME
echo " and cs_policy.context_type = cs_action.context_type" >> $FILENAME
psql -U portal -h localhost < $FILENAME

# List project privileges
echo ""
echo "Project attributes"
echo "select ma_member_attribute.value, cs_attribute.name, cs_action.name, pa_project.project_name " > $FILENAME
echo " from ma_member_attribute, cs_attribute, cs_context_type, cs_assertion, cs_action, cs_policy, pa_project " >> $FILENAME
echo " where ma_member_attribute.value = '$PERSON'" >> $FILENAME
echo " and ma_member_attribute.name = 'username'" >> $FILENAME
echo " and cs_context_type.id = cs_assertion.context_type" >> $FILENAME
echo " and ma_member_attribute.member_id = cs_assertion.principal " >> $FILENAME
echo " and cs_attribute.id = cs_assertion.attribute " >> $FILENAME
echo " and cs_assertion.context_type = 1 " >> $FILENAME
echo " and pa_project.project_id = cs_assertion.context " >> $FILENAME
echo " and cs_policy.attribute = cs_assertion.attribute" >> $FILENAME
echo " and cs_policy.context_type = cs_assertion.context_type" >> $FILENAME
echo " and cs_policy.privilege = cs_action.privilege" >> $FILENAME
echo " and cs_policy.context_type = cs_action.context_type" >> $FILENAME
psql -U portal -h localhost < $FILENAME

# List slice  privileges
echo ""
echo "Slice privileges"
echo "select ma_member_attribute.value, cs_attribute.name, cs_action.name, sa_slice.slice_name " > $FILENAME
echo " from ma_member_attribute, cs_attribute, cs_context_type, cs_assertion, cs_action, cs_policy, sa_slice " >> $FILENAME
echo " where ma_member_attribute.value = '$PERSON'" >> $FILENAME
echo " and ma_member_attribute.name = 'username'" >> $FILENAME
echo " and ma_member_attribute.member_id = cs_assertion.principal " >> $FILENAME
echo " and cs_context_type.id = cs_assertion.context_type" >> $FILENAME
echo " and cs_attribute.id = cs_assertion.attribute " >> $FILENAME
echo " and cs_assertion.context_type = 2 " >> $FILENAME
echo " and sa_slice.slice_id = cs_assertion.context " >> $FILENAME
echo " and cs_policy.attribute = cs_assertion.attribute" >> $FILENAME
echo " and cs_policy.context_type = cs_assertion.context_type" >> $FILENAME
echo " and cs_policy.privilege = cs_action.privilege" >> $FILENAME
echo " and cs_policy.context_type = cs_action.context_type" >> $FILENAME
psql -U portal -h localhost < $FILENAME

#rm $FILENAME


