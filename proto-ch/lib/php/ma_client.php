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

// Client-side interface to GENI Clearinghouse Member Authority (MA)

require_once('ma_constants.php');
require_once('chapi.php');

// A cache of a user's detailed info indexed by member_id
if(!isset($member_cache)) {
  //  error_log("SETTING MEMBER_CACHE");
  $member_cache = array();
  $member_by_attribute_cache = array(); // Only for single attribute lookups
}

// Add member attribute
// CHAPI: ignores $self_asserted
function add_member_attribute($ma_url, $signer, $member_id, $name, $value, $self_asserted)
{
  $member_urn = get_member_urn($member_id);

  $client = new XMLRPCClient($ma_url, $signer);
  $pairs = array(_portalkey_to_attkey($name)=>$value);
  $results = $client->update_member_info($member_urn, $signer->certificate(), $pairs);
  return $results;  // probably ignored
}

// Get list of all member_ids in repository
// CHAPI: ok
function get_member_ids($ma_url, $signer)
{
  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('filter' => array('MEMBER_UID', 'MEMBER_URN')); // match everything, select UID and URN
  $recs = $client->lookup_public_member_info($options);
  $result = array_map(function($x) { return $x['MEMBER_UID']; }, $recs);
  return $result;
}

// Associate SSH public key with user
// CHAPI: ok
function register_ssh_key($ma_url, $signer, $member_id, $filename,
        $description, $ssh_public_key, $ssh_private_key = NULL)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }
  if (! isset($cert) || is_null($cert) || $cert == "") {
    error_log("Cannot register_ssh_key without a user cert");
    throw new Exception("Cannot register_ssh_key without a user cert");
  }

  $client = new XMLRPCClient($ma_url, $signer);
  $member_urn = get_member_urn($member_id);
  $pairs = array('SSH_FILENAME' => $filename,
		 'SSH_DESCRIPTION' => $description,
		 'SSH_PUBLIC_KEY' => $ssh_public_key);
  if (! is_null($ssh_private_key)) {
    $pairs['SSH_PRIVATE_KEY'] = $ssh_private_key;
  }
				    
  $client->update_member_info($member_urn, $cert, $pairs);
}

// Lookup public SSH keys associated with user
function lookup_public_ssh_keys($ma_url, $signer, $member_id)
{
  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('_GENI_MEMBER_SSH_PUBLIC_KEY'));
  $res = $client->lookup_public_member_info($options);
  $ssh_keys = array_map(function($x) { return $x['_GENI_MEMBER_SSH_PUBLIC_KEY']; }, $res);
  return $ssh_keys;
}

// Lookup private SSH keys associated with user
function lookup_private_ssh_keys($ma_url, $signer, $member_id)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }

  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('_GENI_MEMBER_SSH_PRIVATE_KEY'));
  $res = $client->lookup_private_member_info($cert, $options);
  $ssh_keys = array_map(function($x) { return $x['_GENI_MEMBER_SSH_PRIVATE_KEY']; }, $res);
  return $ssh_keys;
}

/*  // removed since there's an obvious typo, so cannot have worked
// Lookup a single SSH key by id
function lookup_public_ssh_key($ma_url, $signer, $member_id, $ssh_key_id)
{
  $keys = lookup_publc_ssh_keys($ma_url, $signer, $member_id);
  foreach ($keys as $key) {
    if ($key[MA_SSH_KEY_TABLE_FIELDNAME::ID] === $ssh_key_id) {
      return $key;
    }
  }
  // No key found, return NULL
  return NULL;
}
*/

function update_ssh_key($ma_url, $signer, $member_id, $ssh_key_id,
        $filename, $description)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }
  if (! isset($cert) || is_null($cert) || $cert == "") {
    error_log("Cannot update_ssh_key without a user cert");
    throw new Exception("Cannot update_ssh_key without a user cert");
  }
  
  $client = new XMLRPCClient($ma_url, $signer);
  $member_urn = get_member_urn($member_id);
  $pairs = array('SSH_KEY_ID' => $ssh_key_id);
  if ($filename) {
    $pairs['SSH_FILENAME'] = $filename;
  }
  if ($description) {
    $pairs['SSH_DESCRIPTION'] = $description;
  }
  $client->update_member_info($member_urn, $cert, $pairs);
    
  //return $ssh_key;
  // CHAPI: no return for now.  If needed, we'll need to retrieve it
}

// CHAPI: unsupported
function delete_ssh_key($ma_url, $signer, $member_id, $ssh_key_id)
{
  $msg = "delete_ssh_key is unimplemented";
  error_log($msg);
  throw new Exception($msg);
}

// Lookup inside keys/certs associated with a user UUID
// CHAPI: need to check return values
function lookup_keys_and_certs($ma_url, $signer, $member_uuid)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }

  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_uuid),
		   'filter'=>array('_GENI_MEMBER_SSH_PRIVATE_KEY'));
  $prires = $client->lookup_private_member_info($cert, $options);
  if (size($prires)>0) {
    $private_key = $prires[0]['_GENI_MEMBER_SSH_PRIVATE_KEY'];
    $puboptions = array('match'=> array('MEMBER_UID'=>$member_uuid),
			'filter'=>array('_GENI_MEMBER_SSH_PUBLIC_KEY'));
    $pubres = $client->lookup_public_member_info($cert, $puboptions);
    if (size($pubres)>0) {
      $public_key = $pubres[0]['_GENI_MEMBER_SSH_PUBLIC_KEY'];
      return array($private_key, $public_key);
    }
  }
  return null;
}

// CHAPI: unsupported
function ma_create_account($ma_url, $signer, $attrs, $self_asserted_attrs)
{
  $msg = "create_account is unimplemented";
  error_log($msg);
  throw new Exception($msg);
}

// map from CHAPI MA attributes to portal attribute keys
$MEMBERALTKEYS = array("MEMBER_URN"=> "urn",
		       "MEMBER_UID"=> "member_id",
		       "MEMBER_FIRSTNAME"=> "first_name",
		       "MEMBER_LASTNAME"=> "last_name",
		       "MEMBER_USERNAME"=> "username",
		       "MEMBER_EMAIL"=> "email_address",
		       "_GENI_MEMBER_DISPLAYNAME"=> "displayName",
		       "_GENI_MEMBER_PHONE_NUMBER"=> "telephone_number",
		       "_GENI_MEMBER_AFFILIATION"=> "affiliation",
		       "_GENI_MEMBER_EPPN"=> "eppn",
		       "_GENI_MEMBER_SSL_PUBLIC_KEY"=> "certificate",
		       "_GENI_MEMBER_SSL_PRIVATE_KEY"=> "private_key",
		       "_GENI_MEMBER_INSIDE_PUBLIC_KEY"=> "certificate",
		       "_GENI_MEMBER_INSIDE_PRIVATE_KEY"=> "private_key",
		       );
function invert_array($ar) {
  $ra = array();
  foreach ($ar as $k => $v) {
    $ra[$v] = $k;
  }
  return $ra;
}
// map that inverts $MEMBERALTKEYS
$MEMBERKEYALTS = invert_array($MEMBERALTKEYS);

function _portalkey_to_attkey($k) {
  if (array_key_exists($k, $MEMBERKEYALTS)) {
    return $MEMBERKEYALTSS[$k];
  } else {
    return $k;
  }
}  

function _attkey_to_portalkey($k) {
  if (array_key_exists($k, $MEMBERALTKEYS)) {
    return $MEMBERALTKEYS[$k];
  } else {
    return $k;
  }
}


// CHAPI: ok
class Member {
  function __construct($id) {
    $this->member_id = $id;
  }
  
  function init_from_record($attrs) {
    foreach ($attrs as $k => $v) {
      $this->{$k} = $v;
      $this->{_attkey_to_portalkey($k)} = $v;
    }
  }
  function prettyName() {
    if (isset($this->displayName)) {
      return $this->displayName;
    } elseif (isset($this->first_name, $this->last_name)) {
      return $this->first_name . " " . $this->last_name;
    } else {
      return $this->eppn;
    }
  }
}

// lookup a member by EPPN.
//   return a member object or null
// CHAPI: new replaced all external uses of ma_lookup_members
function ma_lookup_member_by_eppn($ma_url, $signer, $eppn)
{
  $res =  ma_lookup_member_by_identifying($ma_url, $signer, '_GENI_MEMBER_EPPN', $eppn);
  if ($res) {
    return $res[0];
  } else {
    return null;
  }
}

// lookup one or more members by some identifying key/value.
//   return an array of members (possibly empty)
// replaces uses of ma_lookup_members
// CHAPI: new
function ma_lookup_members_by_identifying($ma_url, $singer, $identifying_key, $identifying_value)
{
  global $member_cache;
  global $member_by_attribute_cache;

  $cache_key = $identifying_key.'.'.$identifying_value;
  if (array_key_exists($cache_key, $member_attribute_cache)) {
    return $member_by_attribute_cache[$cache_key];
  }

  $members = array();

  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array($identifying_key=>$identifying_value));
  $idres = $client->lookup_identifying_member_info($cert, $options);
  foreach ($ires as $idrow) {
    $id = $idrow['MEMBER_UID'];
    $prow = $client->lookup_public_member_info($cert, array('match' => array('MEMBER_UID'=>$id)));
    $m = Member($id);
    $m->init_from_record($ires);
    $m->init_from_record($prow[0]);
    $members[] = $m;
    $member_cache[$id] = $m;
  }
  $member_by_attribute_cache[$cache_key] = $members;

  return $members;
}


//CHAPI:  deleted ma_lookup_members
// $lookup_attrs will = ['eppn' => something]  -> change to ma_lookup_by_eppn
// cache identifying and public
//function ma_lookup_members($ma_url, $signer, $lookup_attrs)

// CHAPI: use CLIENTAUTH as the tail instead of MA
function client_url($ma_url) {
  return preg_replace("/MA$/", "CLIENTAUTH", $ma_url);
}

// List all clients
//CHAPI: done
function ma_list_clients($ma_url, $signer)
{
  $client = new XMLRPCClient(client_url($ma_url), $signer);
  $res = $client->list_clients();
  return $res;
}

// list all clients authorized by the member
//CHAPI: done
function ma_list_authorized_clients($ma_url, $signer, $member_id)
{
  $client = new XMLRPCClient(client_url($ma_url), $signer);
  $res = $client->list_authorized_clients($member_id);
  return $res;
}

// authorize a client
//CHAPI: done
function ma_authorize_client($ma_url, $signer, $member_id, $client_urn,
			     $authorize_sense)
{
  $client = new XMLRPCClient(client_url($ma_url), $signer);
  $res = $client->list_authorize_client($member_id, $client_urn, $authorize_sense);
  return $res;
}

// 
//CHAPI: Now an pseudo-alias for ma_lookup_members_by_identifying(...)[0]
function ma_lookup_member_id($ma_url, $signer, $member_id_key, $member_id_value)
{
  $res = ma_lookup_members_by_identifying($ma_url, $signer, $member_id_key, $member_id_value);
  if (count($res) > 0) {
    return $res[0];
  } else {
    return null;
  }
}

// get the one member (or null) that matches the specified id
// CHAPI: ok
function ma_lookup_member_by_id($ma_url, $signer, $member_id)
{
  $res = ma_lookup_members_by_identifying($ma_url, $signer, 'MEMBER_ID', $member_id);
  if (count($res) > 0) {
    return $res[0];
  } else {
    return null;
  }
}

//CHAPI: error
function ma_create_certificate($ma_url, $signer, $member_id, $csr=NULL)
{
  $msg = "ma_create_certificate is unimplemented";
  error_log($msg);
  throw new Exception($msg);
  /*
  $cert = NULL;
  $private_key = NULL;
  $msg['operation'] = 'ma_create_certificate';
  $msg[MA_ARGUMENT::MEMBER_ID] = $member_id;
  if (isset($csr) && (! is_null($csr))) {
    $msg[MA_ARGUMENT::CSR] = $csr;
  }
  $result = put_message($ma_url, $msg,
          $signer->certificate(), $signer->privateKey());
  return $result;
  */
}

// get '_GENI_MEMBER_SSL_PUBLIC_KEY' (which means certificate)
function ma_lookup_certificate($ma_url, $signer, $member_id)
{
  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('_GENI_MEMBER_SSL_PUBLIC_KEY'));
  $res = $client->lookup_public_member_info($options);
  $ssh_keys = array_map(function($x) { return $x['_GENI_MEMBER_SSL_PUBLIC_KEY']; }, $res);
  return $ssh_keys;
}


// Lookup all details for all members whose ID's are specified
// details will be [memberid => attributes, ...]
// attributes is [at1=>v1, ...]
// where atN is one of DETAILS_PUBLIC, DETAILS_IDENT
//CHAPI: 
function lookup_member_details($ma_url, $signer, $member_uuids)
{
  $client = new XMLRPCClient($ma_url, $signer);
  $result = array();
  foreach ($member_uuids as $uid) {
    $pubdet = _lookup_public_member_details($client, $signer, $uid);
    $iddet = _lookup_identifying_member_details($client, $signer, $uid);
    $attrs = array();
    foreach (array_merge($pubdet,$iddet) as $k => $v) {
      $ak = _attkey_to_portalkey($k);
      $attrs[$k] = $v;
    }
    $result[$uid] = $attrs;
  }
  return $result;
}

$DETAILS_PUBLIC = array(
			"MEMBER_URN",
			"MEMBER_UID",
			"MEMBER_USERNAME",
			"_GENI_MEMBER_SSL_PUBLIC_KEY",
			"_GENI_MEMBER_INSIDE_PUBLIC_KEY",
			"_GENI_USER_CREDENTIAL",
			);

function _lookup_public_member_details($client, $signer, $uid)
{
  $r = $client->lookup_public_member_info(array('match'=>array('MEMBER_UID'=>$uid),
						'filter'=>$DETAILS_PUBLIC));
  if (size($r)>0) {
    return $r[0];
  } else {
    return array();
  }
}

$DETAILS_IDENTIFYING = array(
			     "MEMBER_FIRSTNAME",
			     "MEMBER_LASTNAME",
			     "MEMBER_EMAIL",
			     "_GENI_MEMBER_DISPLAYNAME",
			     "_GENI_MEMBER_PHONE_NUMBER",
			     "_GENI_MEMBER_AFFILIATION",
			     "_GENI_MEMBER_EPPN",
			     );

function _lookup_identifying_member_details($client, $signer, $uid)
{
  $r = $client->lookup_identifying_member_info(array('match'=>array('MEMBER_UID'=>$uid),
						     'filter'=>$DETAILS_IDENTIFYING));
  if (size($r)>0) {
    return $r[0];
  } else {
    return array();
  }
}


// Lookup the display name for all member_ids in a given set of 
// rows, where the member_id is selected by given field name
// Do not include the given signer in the query but add in the response
// If there is no member other than the signer, don't make the query
// CHAPI:okay
function lookup_member_names_for_rows($ma_url, $signer, $rows, $field)
{
  $member_uuids = array();
  foreach($rows as $row) {
    $member_id = $row[$field];
    if($member_id == $signer->account_id || in_array($member_id, $member_uuids)) 
      continue;
    $member_uuids[] = $member_id;
  }
  $names_by_id = array();
  $result = generate_response(RESPONSE_ERROR::NONE, $names_by_id, '');
  if (count($member_uuids) > 0) {
    $names_by_id = lookup_member_names($ma_url, $signer, $member_uuids);
  }
  $names_by_id[$signer->account_id] = $signer->prettyName();
  //  error_log('RESULT = ' . print_r($names_by_id, true));
  return $names_by_id;
}

// Lookup the 'display name' for all members whose ID's are specified
// CHAPI: ok
function lookup_member_names($ma_url, $signer, $member_uuids)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }

  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_emails),
		   'filter'=>array('MEMBER_FIRSTNAME', 'MEMBER_LASTNAME', 'MEMBER_USERNAME'));
  $res = $client->lookup_identifying_member_info($cert, $options);
  $ids = array_map(function($x) { return $x['MEMBER_USERNAME']; }, $res);
  return $ids;
}

// Lookup all members with given email
// Return dictionary email => [member_ids]*
// CHAPI: ok
function lookup_members_by_email($ma_url, $signer, $member_emails)
{
  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }

  $client = new XMLRPCClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_EMAIL'=>$member_emails),
		   'filter'=>array('MEMBER_UID'));
  $res = $client->lookup_identifying_member_info($cert, $options);
  $ids = array_map(function($x) { return $x['MEMBER_UID']; }, $res);
  return array($member_emails => $ids);
}

?>
