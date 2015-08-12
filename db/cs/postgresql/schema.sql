-- Tables for CS (Credential Store) of GENI Prototype Clearinghouse

-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- ----------------------------------------------------------------------
--
-- ----------------------------------------------------------------------
-- Drop the data first, then the type.
DROP TABLE IF EXISTS cs_assertion CASCADE;
DROP TABLE IF EXISTS cs_policy CASCADE;
DROP TABLE IF EXISTS cs_action CASCADE;
DROP TABLE IF EXISTS cs_attribute CASCADE;
DROP TABLE IF EXISTS cs_privilege CASCADE;
DROP TABLE IF EXISTS cs_context_type CASCADE;

-- List of all known attributes/roles on a principal
CREATE TABLE cs_attribute (
   id SERIAL PRIMARY KEY,
   name VARCHAR NOT NULL UNIQUE
);

-- List of all known privileges that a principal may take
CREATE TABLE cs_privilege  (
   id SERIAL PRIMARY KEY,
   name VARCHAR NOT NULL UNIQUE
);

-- A mapping of context type ID to name
CREATE TABLE cs_context_type (
  id SERIAL PRIMARY KEY,
  name VARCHAR NOT NULL UNIQUE
);

-- List of all known actions and the required privilege and context type
CREATE TABLE cs_action (
   id SERIAL PRIMARY KEY,
   name VARCHAR NOT NULL,
   privilege int,
   context_type int NOT NULL REFERENCES cs_context_type(id)
);

-- An assertion is a signed statement that a given principal has a given 
-- attribute, possibly in a given context
CREATE TABLE cs_assertion (
  id SERIAL,
  signer UUID,
  principal UUID NOT NULL,
  attribute INT NOT NULL REFERENCES cs_attribute(id), -- Index into cs_attribute table
  context_type INT NOT NULL REFERENCES cs_context_type(id), -- 0 = NONE, 1 = PROJECT, 2 = SLICE, 3 = SLIVER
  context UUID, 
  expiration TIMESTAMP,
  assertion_cert VARCHAR,
  PRIMARY KEY (id)
);
-- can signer, principal, context by authorities who aren't in tables?

-- A policy is a signed statement that a given holder of a given attribute
-- has a given privilege. Again, this is potentially context dependent.
CREATE TABLE cs_policy (
  id SERIAL PRIMARY KEY,
  signer UUID,
  attribute INT NOT NULL REFERENCES cs_attribute(id), -- Index into cs_attribute
  context_type INT NOT NULL REFERENCES cs_context_type(id), -- 0 = NONE, 1 = PROJECT, 2 = SLICE, 3 = SLIVER
  privilege INT NOT NULL REFERENCES cs_privilege(id), -- Index into cs_privilege
  policy_cert VARCHAR
);


