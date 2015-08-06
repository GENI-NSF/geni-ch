-- Add archiving tables sa_slice_old and sa_slice_member_old
DROP TABLE IF EXISTS sa_slice_old CASCADE;

create TABLE sa_slice_old (
  id SERIAL,
  slice_id UUID, 
  owner_id UUID,
  project_id UUID,
  creation TIMESTAMP,
  expiration TIMESTAMP,
  expired BOOLEAN NOT NULL DEFAULT 'FALSE',
  slice_name VARCHAR,
  slice_urn VARCHAR,
  slice_email VARCHAR,
  certificate VARCHAR,
  slice_description VARCHAR,
  PRIMARY KEY (id)
);

DROP TABLE IF EXISTS sa_slice_member_old CASCADE;
CREATE TABLE sa_slice_member_old (
  id SERIAL,
  slice_id UUID,
  member_id UUID,
  role int,
  PRIMARY KEY (id)
);

