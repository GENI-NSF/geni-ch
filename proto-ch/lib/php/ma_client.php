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
// CHAPI: TODO
function add_member_attribute($ma_url, $signer, $member_id, $name, $value, $self_asserted)
{
  $add_member_attribute_message['operation'] = 'add_member_attribute';
  $add_member_attribute_message[MA_MEMBER_ATTRIBUTE_TABLE_FIELDNAME::MEMBER_ID] = $member_id;
  $add_member_attribute_message[MA_MEMBER_ATTRIBUTE_TABLE_FIELDNAME::NAME] = $name;
  $add_member_attribute_message[MA_MEMBER_ATTRIBUTE_TABLE_FIELDNAME::VALUE] = $value;
  $add_member_attribute_message[MA_MEMBER_ATTRIBUTE_TABLE_FIELDNAME::SELF_ASSERTED] = $self_asserted;
  $results = put_message($ma_url, $add_member_attribute_message, 
			 $signer->certificate(), $signer->privateKey());
  return $results;
}

// Get list of all member_ids in repository
// CHAPI: ok
function get_member_ids($ma_url, $signer)
{
  $client = new XMLRCPClient($ma_url, $signer);
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

  $client = new XMLRCPClient($ma_url, $signer);
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
  $client = new XMLRCPClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('SSH_PUBLIC_KEY'));
  $res = $client->lookup_public_member_info($options);
  $ssh_keys = array_map(function($x) { return $x['SSH_PUBLIC_KEY']; }, $res);
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

  $client = new XMLRCPClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('SSH_PRIVATE_KEY'));
  $res = $client->lookup_private_member_info($cert, $options);
  $ssh_keys = array_map(function($x) { return $x['SSH_PRIVATE_KEY']; }, $res);
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
  
  $client = new XMLRCPClient($ma_url, $signer);
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

  $client = new XMLRCPClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_uuid),
		   'filter'=>array('SSH_PRIVATE_KEY'));
  $res = $client->lookup_private_member_info($cert, $options);
  //$ssh_keys = array_map(function($x) { return $x['SSH_PRIVATE_KEY']; }, $res);
  return $res;
}

// CHAPI: unsupported
function ma_create_account($ma_url, $signer, $attrs,
        $self_asserted_attrs)
{
  $msg = "create_account is unimplemented";
  error_log($msg);
  throw new Exception($msg);
  /*
  $all_attrs = array();
  foreach (array_keys($attrs) as $attr_name) {
    $all_attrs[] = array(MA_ATTRIBUTE::NAME => $attr_name,
            MA_ATTRIBUTE::VALUE => $attrs[$attr_name],
            MA_ATTRIBUTE::SELF_ASSERTED => FALSE);
  }
  foreach (array_keys($self_asserted_attrs) as $attr_name) {
    $all_attrs[] = array(MA_ATTRIBUTE::NAME => $attr_name,
            MA_ATTRIBUTE::VALUE => $self_asserted_attrs[$attr_name],
            MA_ATTRIBUTE::SELF_ASSERTED => TRUE);
  }
  $msg['operation'] = 'create_account';
  $msg[MA_ARGUMENT::ATTRIBUTES] = $all_attrs;
  $result = put_message($ma_url, $msg,
          $signer->certificate(), $signer->privateKey());
  return $result;
  */
}

// CHAPI: ok
class Member {
  function __construct() {
  }
  function init_from_record($record) {
    $this->member_id = $record[MA_ARGUMENT::MEMBER_ID];
    $attrs = $record[MA_ARGUMENT::ATTRIBUTES];
    foreach ($attrs as $attr) {
      $aname = $attr[MA_ATTRIBUTE::NAME];
      $aval = $attr[MA_ATTRIBUTE::VALUE];
      $this->{$aname} = $aval;
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

function ma_lookup_members($ma_url, $signer, $lookup_attrs)
{
  global $member_cache;
  global $member_by_attribute_cache;

  $cache_key = '';
  if (count($lookup_attrs) == 1) {
    $keys = array_keys($lookup_attrs);
    $attr_key = $keys[0];
    $attr_value = $lookup_attrs[$attr_key];
    $cache_key = $attr_key . "." . $attr_value;
      if (array_key_exists($cache_key, $member_by_attribute_cache)) {
	//	error_log("CACHE HIT lookup_members : " . $cache_key);
	return $member_by_attribute_cache[$cache_key];
      }
  }
  $attrs = array();
  foreach (array_keys($lookup_attrs) as $attr_name) {
    $attrs[] = array(MA_ATTRIBUTE::NAME => $attr_name,
            MA_ATTRIBUTE::VALUE => $lookup_attrs[$attr_name]);
  }
  $msg['operation'] = 'lookup_members';
  $msg[MA_ARGUMENT::ATTRIBUTES] = $attrs;
  $members = put_message($ma_url, $msg,
          $signer->certificate(), $signer->privateKey());
  // Somegtimes we get the whole record, not just value, 
  // depending on the controller
  if (array_key_exists(RESPONSE_ARGUMENT::CODE, $members)) {
    if ($members[RESPONSE_ARGUMENT::CODE] != RESPONSE_ERROR::NONE)
      return array();
    $members = $members[RESPONSE_ARGUMENT::VALUE];
  }
  $result = array();
  foreach ($members as $member_info) {
    $member = new Member();
    $member->init_from_record($member_info);
    $member_id = $member_info[MA_ARGUMENT::MEMBER_ID];
    $member_cache[$member_id] = $member;
    $result[] = $member;
  }

  if (count($lookup_attrs) == 1) {
    $member_by_attribute_cache[$cache_key] = $result;
  }
  return $result;
}

function ma_list_clients($ma_url, $signer)
{
  $list_clients_message['operation'] = "ma_list_clients";
  $result = put_message($ma_url, 
			 $list_clients_message, 
			 $signer->certificate(), 
			 $signer->privateKey());
  return $result;
}

function ma_list_authorized_clients($ma_url, $signer, $member_id)
{
  $list_authorized_clients_message['operation'] = "ma_list_authorized_clients";
  $list_authorized_clients_message[MA_ARGUMENT::MEMBER_ID] = $member_id;
  $result = put_message($ma_url, 
			 $list_authorized_clients_message, 
			 $signer->certificate(), 
			 $signer->privateKey());
  return $result;
}

function ma_authorize_client($ma_url, $signer, $member_id, $client_urn,
			     $authorize_sense)
{
  //  error_log("MAAC = " . print_r($authorize_sense, true));

  $authorize_client_message['operation'] = "ma_authorize_client";
  $authorize_client_message[MA_ARGUMENT::MEMBER_ID] = $member_id;
  $authorize_client_message[MA_ARGUMENT::CLIENT_URN] = $client_urn;
  $authorize_client_message[MA_ARGUMENT::AUTHORIZE_SENSE] = $authorize_sense;
  $result = put_message($ma_url, 
			 $authorize_client_message, 
			 $signer->certificate(), 
			 $signer->privateKey());

  //  error_log("MAAC.result = " . print_r($result, true));

  return $result;
}

// Use ma_lookup_members interface
function ma_lookup_member_id($ma_url, $signer, $member_id_key, $member_id_value)
{

  $lookup_attrs[$member_id_key] = $member_id_value;
  $result = ma_lookup_members($ma_url, $signer, $lookup_attrs);

  //  error_log("MALI.RES = " . print_r($result, true));
  return $result;
}

function ma_lookup_member_by_id($ma_url, $signer, $member_id)
{
  global $member_cache;
  if (array_key_exists($member_id, $member_cache)) {
    //    error_log("CACHE HIT lookup_member_by_id: " . $member_id);
    return $member_cache[$member_id];
  }
  $msg['operation'] = 'lookup_member_by_id';
  $msg[MA_ARGUMENT::MEMBER_ID] = $member_id;
  $result = put_message($ma_url, $msg,
          $signer->certificate(), $signer->privateKey());
  // Somegtimes we get the whole record, not just value, 
  // depending on the controller
  if(array_key_exists(RESPONSE_ARGUMENT::CODE, $result)) {
    if ($result[RESPONSE_ARGUMENT::CODE] != RESPONSE_ERROR::NONE)
      return null;
    $result = $result[RESPONSE_ARGUMENT::VALUE];
  }
  $member = new Member();
  $member->init_from_record($result);
  $member_cache[$member_id]=$member;
  return $member;
}

function ma_create_certificate($ma_url, $signer, $member_id, $csr=NULL)
{
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
}

function ma_lookup_certificate($ma_url, $signer, $member_id)
{
  $msg['operation'] = 'ma_lookup_certificate';
  $msg[MA_ARGUMENT::MEMBER_ID] = $member_id;
  $result = put_message($ma_url, $msg,
          $signer->certificate(), $signer->privateKey());
  return $result;
}

// Lookup all details all members whose ID's are specified
function lookup_member_details($ma_url, $signer, $member_uuids)
{
  $msg['operation'] = 'lookup_member_details';
  $msg[MA_ARGUMENT::MEMBER_UUIDS] = $member_uuids;
  $result = put_message($ma_url, $msg, 
			$signer->certificate(), $signer->privateKey());
  return $result;
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

  $client = new XMLRCPClient($ma_url, $signer);
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

  $client = new XMLRCPClient($ma_url, $signer);
  $options = array('match'=> array('MEMBER_EMAIL'=>$member_emails),
		   'filter'=>array('MEMBER_UID'));
  $res = $client->lookup_identifying_member_info($cert, $options);
  $ids = array_map(function($x) { return $x['MEMBER_UID']; }, $res);
  return array($member_emails => $ids);
}

?>
