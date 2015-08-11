-- Replace all actions and policies with simpler project/slice read/write/use
-- scheme, retaining all operator/project_lead privileges

delete from cs_action;

insert into cs_action (name, privilege, context_type) values ('project_read', 2, 1);
insert into cs_action (name, privilege, context_type) values ('project_write', 3, 1);
insert into cs_action (name, privilege, context_type) values ('project_use', 4, 1);
insert into cs_action (name, privilege, context_type) values ('slice_read', 2, 2);
insert into cs_action (name, privilege, context_type) values ('slice_write', 3, 2);
insert into cs_action (name, privilege, context_type) values ('slice_use', 4, 2);
insert into cs_action (name, privilege, context_type) values ('create_project', 3, 3);
insert into cs_action (name, privilege, context_type) values ('administer_members', 3, 5);

delete from cs_policy;

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
