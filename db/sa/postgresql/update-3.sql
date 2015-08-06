-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

ALTER TABLE sa_slice 
    ALTER COLUMN slice_id SET NOT NULL,
    ADD UNIQUE(slice_id),
    ALTER COLUMN owner_id SET NOT NULL,
    ADD FOREIGN KEY (owner_id) REFERENCES ma_member(member_id),
    ALTER COLUMN project_id SET NOT NULL,
    ADD FOREIGN KEY (project_id) REFERENCES pa_project(project_id),
    ALTER COLUMN creation SET NOT NULL,
    ALTER COLUMN slice_name SET NOT NULL,
    ALTER COLUMN slice_urn SET NOT NULL,
    ADD COLUMN private_key VARCHAR; -- supports extending slices reusing the same keypair

ALTER TABLE sa_slice_member 
    ALTER COLUMN slice_id SET NOT NULL,
    ADD FOREIGN KEY (slice_id) REFERENCES sa_slice(slice_id),
    ALTER COLUMN member_id SET NOT NULL,
    ADD FOREIGN KEY (member_id) REFERENCES ma_member(member_id),
    ALTER COLUMN role SET NOT NULL;

CREATE INDEX sa_slice_member_slice_id on sa_slice_member(slice_id);

ALTER TABLE sa_slice_member_request 
    ADD PRIMARY KEY (id),
    ALTER COLUMN context_type SET NOT NULL,
    ALTER COLUMN context_id SET NOT NULL,
    ALTER COLUMN request_type SET NOT NULL,
    ALTER COLUMN requestor SET NOT NULL,
    ADD FOREIGN KEY (requestor) REFERENCES ma_member(member_id),
    ALTER COLUMN status SET NOT NULL,
    ALTER COLUMN status SET DEFAULT '0',
    ALTER COLUMN creation_timestamp SET NOT NULL;

-- _old tables haven't been created yet
CREATE TABLE sa_slice_old (
  id SERIAL,
  slice_id UUID NOT NULL UNIQUE,
  owner_id UUID NOT NULL REFERENCES ma_member (member_id),
  project_id UUID NOT NULL REFERENCES pa_project (project_id),
  creation TIMESTAMP NOT NULL,
  expiration TIMESTAMP,
  expired BOOLEAN NOT NULL DEFAULT 'FALSE',
  slice_name VARCHAR NOT NULL,
  slice_urn VARCHAR NOT NULL,
  slice_email VARCHAR,
  certificate VARCHAR,
  private_key VARCHAR,
  slice_description VARCHAR,
  PRIMARY KEY (id)
);

CREATE TABLE sa_slice_member_old (
  id SERIAL,
  slice_id UUID NOT NULL REFERENCES sa_slice_old (slice_id),
  member_id UUID NOT NULL REFERENCES ma_member(member_id),
  role INT NOT NULL,
  PRIMARY KEY (id)
);
