-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

ALTER TABLE pa_project
   ALTER COLUMN project_id SET NOT NULL,
   ADD UNIQUE (project_id),
   ALTER COLUMN project_name SET NOT NULL,
   ADD UNIQUE (project_name),
   ALTER COLUMN lead_id SET NOT NULL,
   ADD FOREIGN KEY(lead_id) REFERENCES ma_member(member_id),
   ALTER COLUMN creation SET NOT NULL;

-- Postgres implicitly indexes unique columns, so project_id, project_name.
-- lead_id is not indexed unless we do so explicitly

ALTER TABLE pa_project_member
   ALTER COLUMN project_id SET NOT NULL,
   ADD FOREIGN KEY(project_id) REFERENCES pa_project(project_id),
   ALTER COLUMN member_id SET NOT NULL,
   ADD FOREIGN KEY(member_id) REFERENCES ma_member(member_id),
   ALTER COLUMN role SET NOT NULL;

-- Foreign keys are not indexed by default
CREATE INDEX project_member_project_id ON pa_project_member(project_id);
CREATE INDEX project_member_member_id ON pa_project_member(member_id);

ALTER TABLE pa_project_member_request 
   ADD PRIMARY KEY (id),
   ALTER COLUMN context_type SET NOT NULL,
   ALTER COLUMN context_id SET NOT NULL,
   ALTER COLUMN request_type SET NOT NULL,
   ALTER COLUMN requestor SET NOT NULL,
   ADD FOREIGN KEY(requestor) REFERENCES ma_member(member_id),
   ALTER COLUMN status SET NOT NULL,
   ALTER COLUMN status SET DEFAULT '0',
   ALTER COLUMN creation_timestamp SET NOT NULL;

ALTER TABLE pa_project_member_invitation 
   ADD PRIMARY KEY (id),
   ALTER COLUMN invite_id SET NOT NULL,
   ALTER COLUMN project_id SET NOT NULL,
   ADD FOREIGN KEY (project_id) REFERENCES pa_project(project_id);

ALTER TABLE pa_project_attribute 
   ADD FOREIGN KEY (project_id) REFERENCES pa_project(project_id);