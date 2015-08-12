-- Create table of invitations from leads to candidate members
drop TABLE if EXISTS pa_project_member_invitation;
create TABLE pa_project_member_invitation(
       id SERIAL,
       invite_id UUID,
       project_id UUID,
       role INT,
       expiration TIMESTAMP
);
