
-- Add an expired column pa_project table. Projects whose
-- expiration time has passed but aren't yet expired
-- will be periodically checked and expired, causing 
-- a log message, Much like we do for slices.

ALTER TABLE pa_project ADD expired BOOLEAN NOT NULL DEFAULT 'FALSE';

