
-- Now create the archiving table
CREATE TABLE logging_entry_old (
  id SERIAL,
  event_time TIMESTAMP,
  user_id UUID,
  message VARCHAR,
  PRIMARY KEY (id)
);

CREATE TABLE logging_entry_attribute_old (
  event_id INT,
  attribute_name VARCHAR,
  attribute_value VARCHAR
);

