#!/bin/bash

# List privileges for given user
# Usage: list_privileges.sh username

if [ $# -lt 1 ]; then
    echo "Usage: list_privileges.sh person_name"
exit
fi

PERSON=$1

# CS_POLICY : attribute, context_type, privilege
# CS_PRIVILEGE : ID, NAME
# CS_ACTION : ID, NAME, PRIVILEGE, CONTEXT_TYPE

# List privileges with no context
echo "Context-free Privileges:"
psql -U portal -h localhost <<EOF
SELECT who.value, role.name, cs_action.name
 FROM ma_privilege, cs_policy, cs_action, ma_member_attribute AS role
INNER JOIN ma_member_attribute AS who
ON who.member_id = role.member_id
WHERE who.name = 'username'
  AND who.value = '$PERSON'
  AND role.name = 'OPERATOR'
  AND role.value = 'true'
  AND ma_privilege.privilege = upper(role.name)
  AND cs_policy.attribute = 5
  AND cs_policy.context_type IN (1,2,3,4,5)
  AND cs_policy.privilege = cs_action.privilege
  AND cs_policy.context_type = cs_action.context_type
UNION
SELECT who.value, role.name, cs_action.name
 FROM ma_privilege, cs_policy, cs_action, ma_member_attribute AS role
INNER JOIN ma_member_attribute AS who
ON who.member_id = role.member_id
WHERE who.name = 'username'
  AND who.value = '$PERSON'
  AND role.name = 'PROJECT_LEAD'
  AND role.value = 'true'
  AND ma_privilege.privilege = upper(role.name)
  AND cs_policy.attribute = 3
  AND cs_policy.context_type = 1
  AND cs_policy.privilege = cs_action.privilege
  AND cs_policy.context_type = cs_action.context_type
;
EOF

# List project privileges
echo ""
echo "Project attributes"
psql -U portal -h localhost <<EOF
select ma_member_attribute.value, cs_attribute.name, cs_action.name, pa_project.project_name
 from ma_member_attribute, cs_attribute, cs_context_type, pa_project_member, cs_action, cs_policy, pa_project 
 where ma_member_attribute.value = '$PERSON'
 and ma_member_attribute.name = 'username'
 and cs_context_type.id = 3
 and ma_member_attribute.member_id = pa_project_member.member_id
 and cs_attribute.id = pa_project_member.role
 and pa_project.project_id = pa_project_member.project_id
 and cs_policy.attribute = pa_project_member.role
 and cs_policy.context_type = 3
 and cs_policy.privilege = cs_action.privilege
 and cs_policy.context_type = cs_action.context_type;
EOF

# List slice  privileges
echo ""
echo "Slice privileges"
psql -U portal -h localhost <<EOF
select ma_member_attribute.value, cs_attribute.name, cs_action.name, sa_slice.slice_name
 from ma_member_attribute, cs_attribute, cs_context_type, sa_slice_member, cs_action, cs_policy, sa_slice 
 where ma_member_attribute.value = '$PERSON'
 and ma_member_attribute.name = 'username'
 and ma_member_attribute.member_id = sa_slice_member.member_id
 and cs_context_type.id = 2
 and cs_attribute.id = sa_slice_member.role
 and sa_slice.slice_id = sa_slice_member.slice_id
 and cs_policy.attribute = sa_slice_member.role
 and cs_policy.context_type = 2
 and cs_policy.privilege = cs_action.privilege
 and cs_policy.context_type = cs_action.context_type;
EOF


