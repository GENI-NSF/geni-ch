-- Move all context-free assertions (assertions about users that are not
-- connected to a slice or project context)
-- to the MA_MEMBER_ATTRIBUTE table

-- There are essentially two cases:
-- ATTRIBUTE = 1 (LEAD), CONTEXT_TYPE = 3 (RESOURCE) => "PROJECT_LEAD"
-- ATTRIBUTE = 5 (OPERATOR), CONTEXT_TYPE = 3 (RESOURCE) => "OPERATOR"

-- MA_MEMBER_ATTRIBUTE
-- id : integer
-- member_id : uuid
-- name : string
-- value : string
-- self_asserted : Boolean

-- FIXME: Note that if you run this script more than once you will get duplicate entries in ma_member_attribute


-- Move all PROJECT_LEAD (ATT=1, CT = 3) assertions into MA_MEMBER_ATTRIBUTE
-- as 'project_lead: true' attribute
INSERT INTO ma_member_attribute (member_id, name, value, self_asserted)
  SELECT principal, 'PROJECT_LEAD', 'true', 'f'
    FROM cs_assertion
    WHERE context IS NULL
      AND attribute = 1
      AND context_type = 3;

-- Move all OPERATOR (ATT = 5, CT = 3) assertions into MA_MEMBER_ATTRIBUTE
-- as 'operator: true' attribute
INSERT INTO ma_member_attribute (member_id, name, value, self_asserted)
  SELECT principal, 'OPERATOR', 'true', 'f'
    FROM cs_assertion
    WHERE context IS NULL
      AND attribute = 5
      AND context_type = 3;
