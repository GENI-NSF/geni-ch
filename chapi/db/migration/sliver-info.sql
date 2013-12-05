
-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1

-- Add sa_sliver_info table

DROP TABLE if EXISTS sa_sliver_info CASCADE;

CREATE TABLE sa_sliver_info (
       id SERIAL,
       slice_urn varchar not null,
       sliver_urn varchar unique not null,
       creation timestamp without time zone,
       expiration timestamp without time zone,
       creator_urn varchar not null,
       aggregate_urn varchar not null,
       PRIMARY KEY (id)
);
CREATE INDEX sa_sliver_info_urn ON sa_sliver_info(sliver_urn);
