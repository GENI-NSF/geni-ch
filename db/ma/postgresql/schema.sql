-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Tables for the MA (Member Authority)

-- ----------------------------------------------------------------------
-- Member table. Store the member ids. Attribute are in
-- ma_member_attribute.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_member CASCADE;

CREATE TABLE ma_member (
  id SERIAL PRIMARY KEY,
  member_id UUID UNIQUE NOT NULL
);

-- No need to index member_id since it is already declared unique

-- ----------------------------------------------------------------------
-- Member attribute table. Store all attributes of members as name/value
-- pairs keyed to the member id.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_member_attribute;

CREATE TABLE ma_member_attribute (
  id SERIAL PRIMARY KEY,
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  name VARCHAR NOT NULL,
  value VARCHAR NOT NULL,
  self_asserted BOOLEAN NOT NULL
);

CREATE INDEX ma_member_attribute_index_member_id
  ON ma_member_attribute (member_id);

CREATE INDEX ma_member_attribute_name_value 
  ON ma_member_attribute (name, value);

-- ----------------------------------------------------------------------
-- Privilege table. List all available privileges.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_privilege CASCADE;

CREATE TABLE ma_privilege (
  id INT PRIMARY KEY,
  privilege VARCHAR NOT NULL
);

-- ----------------------------------------------------------------------
-- Member privilege table. Store all privileges based on their CS types.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_member_privilege;

CREATE TABLE ma_member_privilege (
  id SERIAL PRIMARY KEY,
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  privilege_id INT NOT NULL REFERENCES ma_privilege (id),
  expiration TIMESTAMP
);

CREATE INDEX ma_member_privilege_index_member_id
  ON ma_member_privilege (member_id);

-- privilege_id not indexed

-- ----------------------------------------------------------------------
-- Client table. Each client has a certificate and is "approved" in
-- some way.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_client CASCADE;

CREATE TABLE ma_client (
  id SERIAL PRIMARY KEY,
  client_name VARCHAR UNIQUE NOT NULL,
  client_urn VARCHAR UNIQUE NOT NULL
);

-- ----------------------------------------------------------------------
-- Inside keys
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_inside_key;

CREATE TABLE ma_inside_key (
  id SERIAL PRIMARY KEY,
  client_urn VARCHAR REFERENCES ma_client (client_urn),
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  private_key VARCHAR NOT NULL,
  certificate VARCHAR NOT NULL,
  expiration TIMESTAMP,
  UNIQUE (client_urn, member_id)
);

CREATE INDEX ma_inside_key_index_member_id ON ma_inside_key (member_id);
-- client_urn is not indexed

-- ----------------------------------------------------------------------
-- ssh keys
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_ssh_key;
CREATE TABLE ma_ssh_key (
  id SERIAL,
  member_id UUID NOT NULL REFERENCES ma_member (member_id),
  filename VARCHAR,
  description VARCHAR,
  public_key VARCHAR NOT NULL,
  private_key VARCHAR,
  key_type VARCHAR,
  PRIMARY KEY (id)
);
CREATE INDEX ma_ssh_key_member_id ON ma_ssh_key (member_id);

-- ----------------------------------------------------------------------
-- Member cert/key for outside tools (for use "outside" the portal).
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS ma_outside_cert;
CREATE TABLE ma_outside_cert (
  id SERIAL PRIMARY KEY,
  member_id UUID REFERENCES ma_member (member_id) NOT NULL,
  certificate VARCHAR NOT NULL,
  private_key VARCHAR,
  expiration TIMESTAMP
);

CREATE INDEX ma_outside_cert_index_member_id ON ma_outside_cert (member_id);
