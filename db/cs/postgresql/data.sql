
-- ----------------------------------------------------------------------
-- A few initial records to insert into the database
-- ----------------------------------------------------------------------

-- Define attributes
INSERT INTO cs_attribute (id, name) values (1, 'LEAD');
INSERT INTO cs_attribute (id, name) values (2, 'ADMIN');
INSERT INTO cs_attribute (id, name) values (3, 'MEMBER');
INSERT INTO cs_attribute (id, name) values (4, 'AUDITOR');
INSERT INTO cs_attribute (id, name) values (5, 'OPERATOR');

-- Define  privileges
INSERT INTO cs_privilege (id, name) values (1, 'DELEGATE'); 
INSERT INTO cs_privilege (id, name) values (2, 'READ');
INSERT INTO cs_privilege (id, name) values (3, 'WRITE');
INSERT INTO cs_privilege (id, name) values (4, 'USE');

-- Define context types
insert into cs_context_type (id, name) values (1, 'PROJECT');
insert into cs_context_type (id, name) values (2, 'SLICE');
insert into cs_context_type (id, name) values (3, 'RESOURCE');
insert into cs_context_type (id, name) values (4, 'SERVICE');
insert into cs_context_type (id, name) values (5, 'MEMBER');

-- Define actions
insert into cs_action (name, privilege, context_type) values ('project_read', 2, 1);
insert into cs_action (name, privilege, context_type) values ('project_write', 3, 1);
insert into cs_action (name, privilege, context_type) values ('project_use', 4, 1);
insert into cs_action (name, privilege, context_type) values ('slice_read', 2, 2);
insert into cs_action (name, privilege, context_type) values ('slice_write', 3, 2);
insert into cs_action (name, privilege, context_type) values ('slice_use', 4, 2);
insert into cs_action (name, privilege, context_type) values ('create_project', 3, 3);
insert into cs_action (name, privilege, context_type) values ('administer_members', 3, 5);

-- Define initial set of policies based on PROJECT/SLICE READ/WRITE/USE
insert into cs_policy (attribute, context_type, privilege) values ('1', '1','2');
insert into cs_policy (attribute, context_type, privilege) values ('1', '1','3');
insert into cs_policy (attribute, context_type, privilege) values ('1', '1','4');
insert into cs_policy (attribute, context_type, privilege) values ('2', '1','2');
insert into cs_policy (attribute, context_type, privilege) values ('2', '1','3');
insert into cs_policy (attribute, context_type, privilege) values ('2', '1','4');
insert into cs_policy (attribute, context_type, privilege) values ('3', '1','2');
insert into cs_policy (attribute, context_type, privilege) values ('3', '1','4');
insert into cs_policy (attribute, context_type, privilege) values ('4', '1','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '1','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '1','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '1','4');
insert into cs_policy (attribute, context_type, privilege) values ('1', '2','2');
insert into cs_policy (attribute, context_type, privilege) values ('1', '2','3');
insert into cs_policy (attribute, context_type, privilege) values ('1', '2','4');
insert into cs_policy (attribute, context_type, privilege) values ('2', '2','2');
insert into cs_policy (attribute, context_type, privilege) values ('2', '2','3');
insert into cs_policy (attribute, context_type, privilege) values ('2', '2','4');
insert into cs_policy (attribute, context_type, privilege) values ('3', '2','2');
insert into cs_policy (attribute, context_type, privilege) values ('3', '2','4');
insert into cs_policy (attribute, context_type, privilege) values ('4', '2','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '2','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '2','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '2','4');
insert into cs_policy (attribute, context_type, privilege) values ('1', '3','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '3','1');
insert into cs_policy (attribute, context_type, privilege) values ('5', '3','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '3','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '4','1');
insert into cs_policy (attribute, context_type, privilege) values ('5', '4','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '4','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '5','1');
insert into cs_policy (attribute, context_type, privilege) values ('5', '5','2');
insert into cs_policy (attribute, context_type, privilege) values ('5', '5','3');
insert into cs_policy (attribute, context_type, privilege) values ('5', '3','4');
insert into cs_policy (attribute, context_type, privilege) values ('5', '4','4');
insert into cs_policy (attribute, context_type, privilege) values ('5', '5','4');
