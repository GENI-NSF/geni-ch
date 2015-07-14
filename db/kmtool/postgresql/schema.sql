-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Tables for the KM

-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS km_asserted_attribute;

CREATE TABLE km_asserted_attribute (
  id SERIAL PRIMARY KEY,
  eppn VARCHAR NOT NULL,
  name VARCHAR NOT NULL,
  value VARCHAR NOT NULL,
  asserter_id UUID,
  created timestamp DEFAULT NOW()
);

CREATE INDEX km_asserted_attribute_eppn ON km_asserted_attribute (eppn);
