
-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- ----------------------------------------------------------------------
--
-- ----------------------------------------------------------------------
-- Drop the data first, then the type.
DROP TABLE IF EXISTS sa_slice CASCADE;

create TABLE sa_slice (
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
  private_key VARCHAR, -- supports extending slices while reusing the same keypair
  slice_description VARCHAR,
  PRIMARY KEY (id)
);

CREATE INDEX sa_slice_expired ON sa_slice (expired);
-- owner_id and project_id are not indexed by default

DROP TABLE IF EXISTS sa_slice_member CASCADE;
CREATE TABLE sa_slice_member (
  id SERIAL,
  slice_id UUID NOT NULL REFERENCES sa_slice (slice_id),
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  role int NOT NULL,
  PRIMARY KEY (id)
);

CREATE INDEX sa_slice_member_member_id on sa_slice_member(member_id);
CREATE INDEX sa_slice_member_slice_id on sa_slice_member(slice_id);

-- These match our common queries, but in my simple tests my DB doesn't use these
-- CREATE INDEX sa_slice_index_name_project ON sa_slice (slice_name, project_id);
-- CREATE INDEX sa_slice_index_slice_id ON sa_slice(slice_id);
-- CREATE INDEX sa_slice_index_project_owner ON sa_slice(project_id, owner_id);
-- CREATE INDEX sa_slice_index_owner ON sa_slice(owner_id);

-- Create tables for requests relative to membership on slices
DROP TABLE IF EXISTS sa_slice_member_request;
CREATE TABLE sa_slice_member_request (
       id SERIAL PRIMARY KEY,
       context_type INT NOT NULL,
       context_id UUID NOT NULL,
       request_text VARCHAR, 
        -- 0 = JOIN, 1 = UPDATE_ATTRIBUTES, 2 = .... [That's all for now]
       request_type INT NOT NULL,
       -- This is a JSON string with a dictionary of requested attributes 
       -- for the case of a user wanting a change to his attributes
       request_details VARCHAR, 
       requestor UUID NOT NULL REFERENCES ma_member (member_id),
       status INT NOT NULL DEFAULT '0', -- 0 = PENDING, 1 = APPROVED, 2 = CANCELED, 3 = REJECTED
       creation_timestamp TIMESTAMP NOT NULL,
       resolver UUID,
       resolution_timestamp TIMESTAMP,
       resolution_description VARCHAR
);

-- Is context_id a slice_id?
-- requestor is not indexed by default

-- Add tables for sliver info in SA

DROP TABLE if EXISTS sa_sliver_info CASCADE;

CREATE TABLE sa_sliver_info (
       id SERIAL,
       slice_urn VARCHAR NOT NULL,
       sliver_urn VARCHAR UNIQUE NOT NULL,
       creation TIMESTAMP WITHOUT TIME ZONE,
       expiration TIMESTAMP WITHOUT TIME ZONE,
       creator_urn VARCHAR NOT NULL,
       aggregate_urn VARCHAR NOT NULL,
       PRIMARY KEY (id)
);
CREATE INDEX sa_sliver_info_urn ON sa_sliver_info(sliver_urn);
-- slice_urn should be a value in sa_slice(slice_urn)

-- Update the schema version
INSERT INTO schema_version
       (key, extra)
VALUES ('006', 'sa_sliver_info');

-- Add archiving tables sa_slice_old and sa_slice_member_old
DROP TABLE IF EXISTS sa_slice_old CASCADE;

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

DROP TABLE IF EXISTS sa_slice_member_old CASCADE;
CREATE TABLE sa_slice_member_old (
  id SERIAL,
  slice_id UUID NOT NULL REFERENCES sa_slice_old (slice_id),
  member_id UUID NOT NULL REFERENCES ma_member(member_id),
  role INT NOT NULL,
  PRIMARY KEY (id)
);

