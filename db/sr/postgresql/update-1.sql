
-- Add the service URN column to the service registry
ALTER TABLE service_registry ADD COLUMN
  service_urn VARCHAR;


-- ig gpo
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+instageni.gpolab.bbn.com+authority+cm'
  WHERE service_url = 'https://www.instageni.gpolab.bbn.com:12369/protogeni/xmlrpc/am/2.0';

-- ig utah
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+utah.geniracks.net+authority+cm'
  WHERE service_url = 'https://www.utah.geniracks.net:12369/protogeni/xmlrpc/am/2.0';

-- pg uky
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+uky.emulab.net+authority+cm'
  WHERE service_url = 'https://www.uky.emulab.net:12369/protogeni/xmlrpc/am/2.0';

-- pgeni3
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+pgeni3.gpolab.bbn.com+authority+cm'
  WHERE service_url = 'https://www.pgeni3.gpolab.bbn.com:12369/protogeni/xmlrpc/am/2.0';

-- utah
UPDATE service_registry
  SET service_urn = 'urn:publicid:IDN+emulab.net+authority+cm'
  WHERE service_url = 'https://www.emulab.net:12369/protogeni/xmlrpc/am/2.0';
