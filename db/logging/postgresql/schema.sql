
-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Drop table to recreate
DROP INDEX IF EXISTS logging_entry_event_time;
DROP INDEX IF EXISTS logging_entry_attribute_event_id;

DROP TABLE IF EXISTS logging_entry_attribute;
DROP TABLE IF EXISTS logging_entry;
DROP TABLE IF EXISTS logging_entry_context;
DROP TABLE IF EXISTS logging_entry_attribute_old;
DROP TABLE IF EXISTS logging_entry_old;

-- Now create the table
CREATE TABLE logging_entry (
  id SERIAL,
  event_time TIMESTAMP NOT NULL,
  user_id UUID, -- could be an authority or null
  message VARCHAR,
  PRIMARY KEY (id)
);

CREATE INDEX logging_entry_event_time ON logging_entry(event_time);

CREATE TABLE logging_entry_attribute (
  event_id INT NOT NULL REFERENCES logging_entry(id),
  attribute_name VARCHAR NOT NULL,
  attribute_value VARCHAR
);

CREATE INDEX logging_entry_attribute_event_id 
      ON logging_entry_attribute(event_id);

-- Now create the table
CREATE TABLE logging_entry_old (
  id SERIAL,
  event_time TIMESTAMP NOT NULL,
  user_id UUID,
  message VARCHAR,
  PRIMARY KEY (id)
);

CREATE TABLE logging_entry_attribute_old (
  event_id INT NOT NULL REFERENCES logging_entry_old(id),
  attribute_name VARCHAR NOT NULL,
  attribute_value VARCHAR
);

