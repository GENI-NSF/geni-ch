-- Replace previous definition of service_registry_attribute table
-- to current (consistent) definition
DROP TABLE IF EXISTS service_registry_attribute;

CREATE TABLE service_registry_attribute (
 id SERIAL PRIMARY KEY,
 service_id INT,
 name VARCHAR,
 value VARCHAR
);
