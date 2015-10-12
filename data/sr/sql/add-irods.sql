-- Create the entry for iRODS
insert into service_registry
    (service_type, service_url, service_urn, service_cert, service_name,
     service_description)
  values (11,
          'https://geni-gimi.renci.org:8443/irods-rest-0.0.1-SNAPSHOT/rest',
          '',
          '/usr/share/geni-ch/sr/certs/irods.pem',
          'iRODS',
          'iRODS REST server');
