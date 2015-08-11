-- -------------------------------------------------------------------
-- Fix some incorrect/undesired privilege semantics
-- -------------------------------------------------------------------

-- Create a new privilege "USE" = 4
INSERT INTO cs_privilege (id, name) values (4, 'USE');


-- Set the create_slice method to be a 'USE' on the project
UPDATE cs_action set privilege = 4 where name = 'create_slice';

-- Give PROJECT USE privilege to LEAD, OPERATOR, ADMIN, MEMBER
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 1, 1, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 1, 2, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 1, 3, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 1, 4, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 1, 5, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 2, 1, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 2, 2, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 2, 3, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 2, 4, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 2, 5, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 3, 1, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 3, 2, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 3, 3, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 3, 4, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 3, 5, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 5, 1, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 5, 2, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 5, 3, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 5, 4, 4, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert) values
       (null, 5, 5, 4, null);





-- Make these actions part of the DELEGATE privilege group
UPDATE cs_action SET privilege = 1 
WHERE name IN ('change_lead', 'add_project_member', 
      'remove_project_member', 'change_member_role');

-- Remove WRITE privileges for PROJECT MEMBERS
DELETE FROM cs_policy WHERE attribute = 3 AND context_type = 1 AND privilege = 3;

-- Make these actions part of the DELEGATE privilege group
UPDATE cs_action SET privilege = 1 
WHERE name IN ('add_slice_member', 'remove_slice_member', 
      'change_slice_member_role'); 

-- Remove the action 'delete_slice' : no such thing
DELETE FROM cs_action WHERE name = 'delete_slice';

