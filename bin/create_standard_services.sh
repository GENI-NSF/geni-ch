#!/bin/bash

# To create service certs and SQL:
# bin/geni-init-services --sql services.sql /etc/geni-ch/ch-services.ini

# To add the services to the database (see above)
# psql -U portal -h localhost -f services.sql portal

# To add the portal:
# geni-add-trusted-tool -d portal --host localhost -u portal portal \
#                       urn:publicid:IDN+ch.geni.net+authority+portal


echo
echo "Warning: create_standard_services.sh is obsolete."
echo
echo "    Use 'geni-init-services' to create service certificates and SQL."
echo "    Use 'geni-add-trusted-tool' to add the portal to the database."
echo
