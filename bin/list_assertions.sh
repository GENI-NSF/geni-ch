#!/bin/bash

# List assertions for given user
# Usage: list_assertions.sh username

if [ $# -lt 1 ]; then
    echo "Usage: list_assertions.sh person_name"
exit
fi

PERSON=$1

# List assertions with no context
echo "Context-free Assertions:"
psql -U portal -h localhost <<EOF
SELECT who.value, role.name
FROM ma_member_attribute AS role
INNER JOIN ma_member_attribute AS who
ON who.member_id = role.member_id
WHERE who.name = 'username'
  AND who.value = '$PERSON'
  AND role.name in ('OPERATOR', 'PROJECT_LEAD')
  AND role.value = 'true';
EOF

# List project assertions
echo ""
echo "Project assertions:"
psql -U portal -h localhost <<EOF
select ma_member_attribute.value, cs_attribute.name, cs_context_type.name, pa_project.project_name
 from ma_member_attribute, cs_attribute, cs_context_type, pa_project, pa_project_member 
 where ma_member_attribute.name='username'
 and ma_member_attribute.value = '$PERSON'
 and ma_member_attribute.member_id = pa_project_member.member_id
 and cs_context_type.id = 3
 and cs_attribute.id = pa_project_member.role
 and pa_project.project_id = pa_project_member.project_id
EOF

# List slice  assertions
echo ""
echo "Slice assertions:"
psql -U portal -h localhost <<EOF
select ma_member_attribute.value, cs_attribute.name, cs_context_type.name, sa_slice.slice_name
 from ma_member_attribute, cs_attribute, cs_context_type, sa_slice, sa_slice_member 
 where ma_member_attribute.name='username'
 and ma_member_attribute.value = '$PERSON'
 and ma_member_attribute.member_id = sa_slice_member.member_id
 and cs_context_type.id = 2
 and cs_attribute.id = sa_slice_member.role
 and sa_slice.slice_id = sa_slice_member.slice_id 
EOF
