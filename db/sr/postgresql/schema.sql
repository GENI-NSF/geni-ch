
-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Drop tables to recreate
DROP TABLE IF EXISTS service_registry_attribute;
DROP TABLE IF EXISTS service_registry;

-- Now create the tables

CREATE TABLE service_registry (
  id SERIAL,
  service_type INT NOT NULL,
  service_url VARCHAR NOT NULL,
  service_urn VARCHAR,
  service_cert VARCHAR,
  service_name VARCHAR,
  service_description VARCHAR,
  short_name VARCHAR,
  PRIMARY KEY (id)
);

CREATE TABLE service_registry_attribute (
 id SERIAL PRIMARY KEY,
 service_id INT NOT NULL REFERENCES service_registry,
 name VARCHAR,
 value VARCHAR
);

-- service_id is not indexed

-- Common query but DB not using it ?yet?
-- CREATE INDEX service_registry_index_type ON service_registry(service_type);
