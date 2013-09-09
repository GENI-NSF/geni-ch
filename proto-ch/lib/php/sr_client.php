<?php
//----------------------------------------------------------------------
// Copyright (c) 2012-2013 Raytheon BBN Technologies
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and/or hardware specification (the "Work") to
// deal in the Work without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Work, and to permit persons to whom the Work
// is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Work.
//
// THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
// IN THE WORK.
//----------------------------------------------------------------------

// Routines to help clients of the service registry

require_once('sr_constants.php');
require_once('session_cache.php');
require_once('client_utils.php');
require_once('chapi.php');

const SERVICE_REGISTRY_CACHE_TAG = 'service_registry_cache';
const SERVICE_REGISTRY_CACHE_TIMEOUT = 300;

$SRCHAPI2PORTAL = array('SERVICE_ID' => SR_TABLE_FIELDNAME::SERVICE_ID, 
			'SERVICE_TYPE' => SR_TABLE_FIELDNAME::SERVICE_TYPE,
			'SERVICE_URL' => SR_TABLE_FIELDNAME::SERVICE_URL, 
			'SERVICE_URN' => SR_TABLE_FIELDNAME::SERVICE_URN, 
			'SERVICE_CERTIFICATE' => SR_TABLE_FIELDNAME::SERVICE_CERT,
			'SERVICE_NAME' => SR_TABLE_FIELDNAME::SERVICE_NAME,
			'SERVICE_DESCRIPTION' => SR_TABLE_FIELDNAME::SERVICE_DESCRIPTION,
			'SERVICE_TYPE' => SR_TABLE_FIELDNAME::SERVICE_TYPE);


function service_chapi2portal($row) {
  global $SRCHAPI2PORTAL;
  $converted_row = convert_row($row, $SRCHAPI2PORTAL);
  return $converted_row;
}

// Return all services in registry
//CHAPI: ok
function get_services()
{

  $sr_url = get_sr_url();
  //  error_log("SR_URL = " . $sr_url);
  $ver = session_cache_lookup(SERVICE_REGISTRY_CACHE_TAG, SERVICE_REGISTRY_CACHE_TIMEOUT, $sr_url, 'get_version', null);
  $fields = $ver['FIELDS'];
  $client = new XMLRPCClient($sr_url);
  $services = $client->get_services();
  $converted_services = array();
  foreach ($services as $service) { $converted_services[] = service_chapi2portal($service); }
  return $converted_services;

  /*

  $fields = array('SERVICE_URN', 'SERVICE_URL','SERVICE_NAME','SERVICE_DESCRIPTION');  // 'SERVICE_CERT' breaks it
  $options = array('filter' => $fields); 
  $services = array();
  $mas = $client->call(SR_XMLRPC_API::LOOKUP_MEMBER_AUTHORITIES, $options);
  if ($mas) {
    foreach ($mas as &$el) {
      $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::MEMBER_AUTHORITY;
    }
    $services = $mas; 
  }
  $sas = $client->call(SR_XMLRPC_API::LOOKUP_SLICE_AUTHORITIES, $options);
  if ($sas) {
    foreach ($sas as &$el) {
      $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::SLICE_AUTHORITY;
    }
    $services = array_merge($services, $sas); 
  }
  $ags = $client->call(SR_XMLRPC_API::LOOKUP_AGGREGATES, $options);
  if ($ags) { 
        foreach ($ags as &$el) {
	  $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::AGGREGATE_MANAGER;
	}
     $services = array_merge($services, $ags);
  }
  return $services;
  */
}

// Return all services in registry of given type
//CHAPI: ok
function get_services_of_type($service_type)
{
  $services = get_services();
  return select_services($services, $service_type);
}

// Get URL of first registered service of given service type
//CHAPI: ok
function get_first_service_of_type($service_type)
{
  global $SR_SERVICE_TYPE_NAMES;
  $sot = get_services_of_type($service_type);
  if (isset($sot) && ! is_null($sot) && is_array($sot) && count($sot) > 0) {
    return $sot[0][SR_TABLE_FIELDNAME::SERVICE_URL];
  } else {
    error_log("Got back 0 cached services of type " . $SR_SERVICE_TYPE_NAMES[$service_type]);
    return null;
  }
}

// Return the service with the given id, or NULL if no service has the
// given id.
//CHAPI: ok
function get_service_by_id($service_id)
{
  $services = get_services();
  foreach($services as $service) {
    if ($service[SR_TABLE_FIELDNAME::SERVICE_ID] == $service_id) {
      return $service;
    }
  }
  return null;
}

// Lookup services by sets of attributes ("OR OF ANDS"): Any one set must
// match entirely
//CHAPI: unsupported
function get_services_by_attributes($attribute_sets)
{
  //  $sr_url = get_sr_url();
  //  $message['operation'] = 'get_services_by_attributes';
  //  $message[SR_ARGUMENT::SERVICE_ATTRIBUTE_SETS] = $attribute_sets;
  //  $result = put_message($sr_url, $message);

  error_log("CHAPI: unsupported");
  $result = array();

  return $result;
}

// Doesn't work over CHAPI?
//CHAPI: unsupported
function get_attributes_for_service($service_id)
{
  //$sr_url = get_sr_url();
  //  $message['operation'] = 'get_attributes_for_service';
  //  $message[SR_ARGUMENT::SERVICE_ID] = $service_id;
  //  $result = put_message($sr_url, $message);
  error_log("CHAPI: unsupported");
  $result = array();
  return $result;
}

// Register service of given type and URL with registry
//CHAPI: unsupported
function register_service($service_type, $service_url, $service_cert, 
			  $service_name, $service_description, 
			  $service_attributes)
{
  //  $sr_url = get_sr_url();
  //  $message['operation'] = 'register_service';
  //  $message[SR_ARGUMENT::SERVICE_TYPE] = $service_type;
  //  $message[SR_ARGUMENT::SERVICE_URL] = $service_url;
  //  $message[SR_ARGUMENT::SERVICE_CERT] = $service_cert;
  //  $message[SR_ARGUMENT::SERVICE_NAME] = $service_name;
  //  $message[SR_ARGUMENT::SERVICE_DESCRIPTION] = $service_description;
  //  $message[SR_ARGUMENT::SERVICE_ATTRIBUTES] = $service_attributes;
  //  $result = put_message($sr_url, $message);

  //  // Refresh cache
  //  session_cache_flush(SERVICE_REGISTRY_CACHE_TAG);

  error_log("CHAPI: unsupported");
  $result = array();
  
  return $result;
}

// Remove given service of given ID from registry
//CHAPI: unsupported
function remove_service($service_id)
{
  //  $sr_url = get_sr_url();
  //  $message['operation'] = 'remove_service';
  //  $message[SR_ARGUMENT::SERVICE_ID] = $service_id;
  //  $result = put_message($sr_url, $message);
  //
  //  // Refresh cache
  //  session_cache_flush(SERVICE_REGISTRY_CACHE_TAG);

  error_log("CHAPI: unsupported");
  $result = array();

  return $result;
}

// Return all aggregates
//CHAPI: new
function get_aggregates()
{
  $sr_url = get_sr_url();
  $ver = session_cache_lookup(SERVICE_REGISTRY_CACHE_TAG, SERVICE_REGISTRY_CACHE_TIMEOUT, $sr_url, 'get_version', null);
  $fields = $ver['FIELDS'];
  $client = new XMLRPCClient($sr_url);
  $fields = array('SERVICE_URN', 'SERVICE_URL','SERVICE_NAME','SERVICE_DESCRIPTION');  // 'SERVICE_CERT' breaks it
  $options = array('filter' => $fields); 
  $services = array();
  $ags = $client->call(SR_XMLRPC_API::LOOKUP_AGGREGATES, $options);
  if ($ags) { 
    foreach ($ags as &$el) {
      $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::AGGREGATE_MANAGER;
    }
    $services = $ags;
  }
  return $services;
}

// Return all MAs
//CHAPI: new
function get_member_authorities()
{
  $sr_url = get_sr_url();
  $ver = session_cache_lookup(SERVICE_REGISTRY_CACHE_TAG, SERVICE_REGISTRY_CACHE_TIMEOUT, $sr_url, 'get_version', null);
  $fields = $ver['FIELDS'];
  $client = new XMLRPCClient($sr_url);
  $fields = array('SERVICE_URN', 'SERVICE_URL','SERVICE_NAME','SERVICE_DESCRIPTION');  // 'SERVICE_CERT' breaks it
  $options = array('filter' => $fields); 
  $services = array();
  $mas = $client->call(SR_XMLRPC_API::LOOKUP_MEMBER_AUTHORITIES, $options);
  if ($mas) {
    foreach ($mas as &$el) {
      $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::MEMBER_AUTHORITY;
    }
    $services = $mas; 
  }
  return $services;
}

// Return all slice authorities
//CHAPI: new
function get_slice_authorities()
{
  $sr_url = get_sr_url();
  $ver = session_cache_lookup(SERVICE_REGISTRY_CACHE_TAG, SERVICE_REGISTRY_CACHE_TIMEOUT, $sr_url, 'get_version', null);
  $fields = $ver['FIELDS'];
  $client = new XMLRPCClient($sr_url);
  $fields = array('SERVICE_URN', 'SERVICE_URL','SERVICE_NAME','SERVICE_DESCRIPTION');  // 'SERVICE_CERT' breaks it
  $options = array('filter' => $fields); 
  $services = array();
  $sas = $client->call(SR_XMLRPC_API::LOOKUP_SLICE_AUTHORITIES, $options);
  if ($sas) {
    foreach ($sas as &$el) {
      $el[SR_TABLE_FIELDNAME::SERVICE_TYPE]=SR_SERVICE_TYPE::SLICE_AUTHORITY;
    }
    $services = $sas;
  }
  return $services;
}

// Return the authorities for given URNs
//CHAPI: new
function lookup_authorities_for_urns($urns)
{
  $client = new XMLRPCClient(get_sr_url());
  $urls = $client->lookup_authorities_for_urns($urns);
  return $urls;
}

// Return the trust roots for this CH
//CHAPI: new
function get_trust_roots()
{
  $client = new XMLRPCClient(get_sr_url(), null, TRUE);  // unprotected, but return is raw
  $certs = $client->get_trust_roots();
  return $certs;
}


// Helper function to select only services of type
// from a complete list of services
// That is, if you call 'get_services', you can call this
// with the result instead of subsequent calls to 'get_services_of_type'
function select_services($services, $service_type)
{
  $selected = array();
  foreach ($services as $service) {
    if($service[SR_TABLE_FIELDNAME::SERVICE_TYPE] == $service_type) {
      $selected[] = $service;
    }
  }
  return $selected;
}


?>
