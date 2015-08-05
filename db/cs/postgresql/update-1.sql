
-- -------------------------------------------------------------------
-- Add an OPERATOR, and give OPERATORs all privileges in all contexts.
-- -------------------------------------------------------------------

-- Add an OPERATOR attribute
INSERT INTO cs_attribute (id, name) values (5, 'OPERATOR');

-- An OPERATOR of a context_type has DELEGATE, READ AND WRITE PRIVILEGE
-- in that context
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 1, 1, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 1, 2, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 1, 3, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 2, 1, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 2, 2, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 2, 3, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 3, 1, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 3, 2, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 3, 3, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 4, 1, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 4, 2, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 4, 3, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 5, 1, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 5, 2, null);
INSERT INTO cs_policy (signer, attribute, context_type, privilege, policy_cert)
  VALUES (null, 5, 5, 3, null);
