------
------ Add support for new 'invite_member' action in PA
------
INSERT INTO cs_action (name, privilege, context_type) values ('invite_member', 1, 1);
