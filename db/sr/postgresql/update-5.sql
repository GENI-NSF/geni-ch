
-- avoid innocuous NOTICEs about automatic sequence creation
set client_min_messages='WARNING';

-- Tell psql to stop on an error. Default behavior is to proceed.
\set ON_ERROR_STOP 1


-- Delete aggregate attributes
delete from service_registry_attribute;

-- Delete aggregate entries from service registry
delete from service_registry where service_type = 0;

-- Delete aggregate SSL/CA entries from service registry
delete from service_registry
  where service_type = 7
    and service_cert like '/usr/share/geni-ch/sr/certs/%.pem';

delete from service_registry
  where service_type = 7
    and service_cert like '/usr/share/geni-chapi/sr/certs/%.pem';

