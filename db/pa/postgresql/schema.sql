-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Tables for the PA (Project Authority)
-- ----------------------------------------------------------------------
--
-- ----------------------------------------------------------------------
-- Drop the data first, then the type.
DROP TABLE IF EXISTS pa_project CASCADE;

CREATE TABLE pa_project (
  id SERIAL PRIMARY KEY,
  project_id UUID UNIQUE NOT NULL,
  project_name VARCHAR UNIQUE NOT NULL,
  lead_id UUID NOT NULL REFERENCES ma_member (member_id),
  project_email VARCHAR,
  project_purpose VARCHAR,
  creation TIMESTAMP NOT NULL,
  expiration TIMESTAMP,
  expired BOOLEAN NOT NULL DEFAULT 'FALSE'
);

-- Postgres implicitly indexes unique columns, so project_id, project_name.

-- lead_id is not indexed unless we do so explicitly

-- These are for common queries, but so far the DB doesn't use these. Tables too small?
-- CREATE INDEX project_index_project_id ON pa_project (project_id);
-- CREATE INDEX project_index_lead_project ON pa_project (lead_id, project_id);

DROP TABLE IF EXISTS pa_project_member CASCADE;
CREATE TABLE pa_project_member (
  id SERIAL PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES pa_project (project_id),
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  role int NOT NULL
);

-- Foreign keys are not indexed by default
CREATE INDEX project_member_project_id ON pa_project_member(project_id);
CREATE INDEX project_member_member_id ON pa_project_member(member_id);

-- Create tables for requests relative to membership on projects
drop TABLE IF EXISTS pa_project_member_request;
create table pa_project_member_request (
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
       resolver UUID, -- if an authority can resolve then it isn't a member_id
       resolution_timestamp TIMESTAMP,
       resolution_description VARCHAR
);

-- requestor is not indexed by default
-- Is context_id a project_id?

-- Create table of invitations from leads to candidate members
drop TABLE if EXISTS pa_project_member_invitation;
create TABLE pa_project_member_invitation(
       id SERIAL PRIMARY KEY,
       invite_id UUID NOT NULL,
       project_id UUID NOT NULL REFERENCES pa_project (project_id),
       role INT,
       expiration TIMESTAMP
);

-- project_id is not indexed by default

-- ----------------------------------------------------------------------
-- Project attribute table. Store all attributes of project as name/value
-- pairs keyed to the project id.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS pa_project_attribute;

CREATE TABLE pa_project_attribute (
  id SERIAL PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES pa_project (project_id),
  name VARCHAR NOT NULL,
  value VARCHAR NOT NULL
);

CREATE INDEX pa_project_attribute_index_project_id
  ON pa_project_attribute (project_id);
