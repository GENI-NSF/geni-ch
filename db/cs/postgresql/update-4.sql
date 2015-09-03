------
------ Add support for new bulk membership management services in SA, PA
------
INSERT INTO cs_action (name, privilege, context_type) values ('modify_slice_membership', 1, 2);
INSERT INTO cs_action (name, privilege, context_type) values ('modify_project_membership', 1, 1);

