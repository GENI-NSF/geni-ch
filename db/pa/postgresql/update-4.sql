-- ----------------------------------------------------------------------
-- Project attribute table. Store all attributes of project as name/value
-- pairs keyed to the project id.
-- ----------------------------------------------------------------------
DROP TABLE IF EXISTS pa_project_attribute;

CREATE TABLE pa_project_attribute (
  id SERIAL PRIMARY KEY,
  project_id UUID NOT NULL,
  name VARCHAR NOT NULL,
  value VARCHAR NOT NULL
);

CREATE INDEX pa_project_attribute_index_project_id
  ON pa_project_attribute (project_id);
