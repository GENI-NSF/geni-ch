-- Add Exo AM URNs

-- eg gpo
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+exogeni.net:bbnvmsite+authority+am'
  WHERE service_url = 'https://bbn-hn.exogeni.net:11443/orca/xmlrpc';

-- eg renci
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+exogeni.net:rcivmsite+authority+am'
  WHERE service_url = 'https://rci-hn.exogeni.net:11443/orca/xmlrpc';

-- eg exosm
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+exogeni.net+authority+am'
  WHERE service_url = 'https://geni.renci.org:11443/orca/xmlrpc';

