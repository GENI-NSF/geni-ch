-- -------------------
-- Apply changes to add unique and no null and foreign key constraints, and related indices
-- See chapi #174, proto-ch #943, proto-ch #1081
-- -------------------

ALTER TABLE logging_entry
   ALTER COLUMN event_time SET NOT NULL;

ALTER TABLE logging_entry_attribute 
   ALTER COLUMN event_id SET NOT NULL,
   ADD FOREIGN KEY (event_id) REFERENCES logging_entry(id),
   ALTER COLUMN attribute_name SET NOT NULL;

-- Somehow these 2 tables were never created by a previous update script, so do it now

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

