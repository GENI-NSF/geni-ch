
-- Add an expiration column to the pa_project table. Existing projects
-- will not have an expiration time, and thus will never expire. New
-- projects will either be configured to expire at a given date/time,
-- or will have no expiration and never expire.

ALTER TABLE pa_project ADD expiration TIMESTAMP;
