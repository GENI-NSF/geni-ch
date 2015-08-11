------
------ Add support for other SA/PA methods
------
-- PA
INSERT INTO cs_action (name, privilege, context_type) values ('lookup_projects', 2, 3);
INSERT INTO cs_action (name, privilege, context_type) values ('lookup_project_details', 2, 3);
INSERT INTO cs_action (name, privilege, context_type) values ('lookup_project_attributes', 2, 1);
INSERT INTO cs_action (name, privilege, context_type) values ('add_project_attribute', 3, 1);
UPDATE cs_action SET context_type = 3 where name = 'get_projects_for_member';

-- accept_invitation

-- SA
INSERT INTO cs_action (name, privilege, context_type) values ('lookup_slice_by_urn', 2, 2);
INSERT INTO cs_action (name, privilege, context_type) values ('lookup_slice_details', 2, 2);
INSERT INTO cs_action (name, privilege, context_type) values ('get_slices_for_projects', 2, 2);
