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
  $member_urn = get_member_urn($ma_url, $signer, $member_id);

  $client = XMLRPCClient::get_client($ma_url, $signer);
  $pairs = array(_portalkey_to_attkey($name)=>$value);
  $results = $client->update_member_info($member_urn, $client->creds(), $pairs);
  return $results;  // probably ignored
}

// Get list of all member_ids in repository
function get_member_ids($ma_url, $signer)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('filter' => array('MEMBER_UID', 'MEMBER_URN')); // match everything, select UID and URN
  $recs = $client->lookup_public_member_info($client->creds(), 
					     $options);
  $result = array_map(function($x) { return $x['MEMBER_UID']; }, $recs);
  return $result;
}

// Associate SSH public key with user
function register_ssh_key($ma_url, $signer, $member_id, $filename,
        $description, $ssh_public_key, $ssh_private_key = NULL)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $member_urn = get_member_urn($ma_url, $signer, $member_id);
  $pairs = array('_GENI_KEY_FILENAME' => $filename,
                 'KEY_DESCRIPTION' => $description,
                 'KEY_PUBLIC' => $ssh_public_key);
  if (! is_null($ssh_private_key)) {
    $pairs['KEY_PRIVATE'] = $ssh_private_key;
  }

  $client->create_key($member_urn, $client->creds(), array('fields' => $pairs));
}

// Lookup public SSH keys associated with user
function lookup_public_ssh_keys($ma_url, $signer, $member_id)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('_GENI_KEY_MEMBER_UID'=>$member_id),
		   'filter'=>array('KEY_PUBLIC', '_GENI_KEY_FILENAME', 'KEY_DESCRIPTION', 'KEY_ID', '_GENI_KEY_MEMBER_UID'));
  $res = $client->lookup_keys($client->creds(), $options);
  $ssh_keys = array_map(function($x) { 
      return array('id' => $x['KEY_ID'],
		   'public_key' => $x['KEY_PUBLIC'],
		   'description' => $x['KEY_DESCRIPTION'],
		   'member_id' => $x['_GENI_KEY_MEMBER_UID'],
		   'filename' => $x['_GENI_KEY_FILENAME']); }, $res);
  return $ssh_keys;
}

// Lookup private SSH keys associated with user
function lookup_private_ssh_keys($ma_url, $signer, $member_id)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('_GENI_KEY_MEMBER_UID'=>$member_id),
		   'filter'=>array('KEY_PRIVATE', 'KEY_PUBLIC', '_GENI_KEY_FILENAME', 'KEY_DESCRIPTION', 'KEY_ID', '_GENI_KEY_MEMBER_UID'));
  $res = $client->lookup_keys($client->creds(), $options);
  $ssh_keys = array_map(function($x) { 
      return array('id' => $x['KEY_ID'],
		   'private_key' => $x['KEY_PRIVATE'],
		   'public_key' => $x['KEY_PUBLIC'],
		   'description' => $x['KEY_DESCRIPTION'],
		   'member_id' => $x['_GENI_KEY_MEMBER_UID'],
		   'filename' => $x['_GENI_KEY_FILENAME']); }, $res);
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
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $member_urn = get_member_urn($ma_url, $signer, $member_id);
  $pairs = array();
  if ($filename || $filename == '') {
    $pairs['_GENI_KEY_FILENAME'] = $filename;
  }
  if ($description || $description == '') {
    $pairs['KEY_DESCRIPTION'] = $description;
  }
  if (sizeof($pairs) > 0) {
    $client->update_key($member_urn, $ssh_key_id, $client->creds(),
                      array('fields' => $pairs));
  }

  //return $ssh_key;
  // CHAPI: no return for now.  If needed, we'll need to retrieve it
}

function delete_ssh_key($ma_url, $signer, $member_id, $ssh_key_id)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $member_urn = get_member_urn($ma_url, $signer, $member_id);
  $client->delete_key($member_urn, $ssh_key_id, $client->creds(),
                      array('_dummy' => null));
}

// Lookup inside keys/certs associated with a user UUID
function lookup_keys_and_certs($ma_url, $signer, $member_uuid)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_uuid),
		   'filter'=>array('_GENI_MEMBER_INSIDE_PRIVATE_KEY'));
  $prires = $client->lookup_private_member_info($client->creds(), $options);
  //  error_log("PRIRES_OPTS = " . print_r($options, true));
  //  error_log("PRIRES = " . print_r($prires, true));
  if (sizeof($prires)>0) {
    $all_urns = array_keys($prires);
    $urn = $all_urns[0];
    $private_key = $prires[$urn]['_GENI_MEMBER_INSIDE_PRIVATE_KEY'];
    $puboptions = array('match'=> array('MEMBER_UID'=>$member_uuid),
			'filter'=>array('_GENI_MEMBER_INSIDE_CERTIFICATE'));
    $pubres = $client->lookup_public_member_info($client->creds(), 
						 $puboptions);
    if (sizeof($pubres)>0) {
      $certificate = $pubres[$urn]['_GENI_MEMBER_INSIDE_CERTIFICATE'];
      return array(MA_INSIDE_KEY_TABLE_FIELDNAME::CERTIFICATE => $certificate,
		   MA_INSIDE_KEY_TABLE_FIELDNAME::PRIVATE_KEY=> $private_key);
    }
  }
  return null;
}

// CHAPI: unsupported
function ma_create_account($ma_url, $signer, $attrs, $self_asserted_attrs)
{
//  error_log("IN MA_CREATE_ACCOUNT " + print_r($attrs, true) + " " + print_r($self_asserted_attrs, true));
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

  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('_dummy' => null);
  $results = $client->create_member($all_attrs, $client->creds(), $options);
  
//  error_log("MA_CREATE_ACCOUNT.results = " . print_r($results, true));
  
  // return member_id
  return $results[0]['member_id'];
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
  global $MEMBERKEYALTS;
  if (array_key_exists($k, $MEMBERKEYALTS)) {
    return $MEMBERKEYALTS[$k];
  } else {
    return $k;
  }
}  

function _attkey_to_portalkey($k) {
  global $MEMBERALTKEYS;
  if (array_key_exists($k, $MEMBERALTKEYS)) {
    return $MEMBERALTKEYS[$k];
  } else {
    return $k;
  }
}


// member abstration class
class Member {
  function __construct($id=null) {
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
function ma_lookup_member_by_eppn($ma_url, $signer, $eppn)
{
  //error_log( " lookup_member_by_eppn = " . print_r($eppn, true));
  $res =  ma_lookup_members_by_identifying($ma_url, $signer, '_GENI_MEMBER_EPPN', $eppn);
  if ($res) {
    return $res[0];
  } else {
    return null;
  }
}

// lookup one or more members by some identifying key/value.
//   return an array of members (possibly empty)
// replaces uses of ma_lookup_members
function ma_lookup_members_by_identifying($ma_url, $signer, $identifying_key, $identifying_value)
{
  global $member_cache;
  global $member_by_attribute_cache;

  $cache_key = $identifying_key.'.'.$identifying_value;
  if (array_key_exists($cache_key, $member_by_attribute_cache)) {
    return $member_by_attribute_cache[$cache_key];
  }

  $members = array();

  //error_log( " lookup_members_by_identifying = " . print_r($identifying_key, true) . " // ". print_r($identifying_value, true));

  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array($identifying_key=>$identifying_value));
  $pubres = $client->lookup_public_member_info($client->creds(), 
					       $options);
  //  error_log( " PUBRES = " . print_r($pubres, true));
  
  $ids = array();
  foreach ($pubres as $urn => $pubrow) {
    $ids[] = $pubrow['MEMBER_UID'];
  }
  $idrow = $client->lookup_identifying_member_info($client->creds(), 
						   array('match' => array('MEMBER_UID'=>$ids)));
  //    error_log("   ID = " . print_r($id, true));
  //    error_log("   IDROW = " . print_r($idrow, true));
  foreach ($pubres as $urn => $pubrow) {
    //    error_log("   URN = " . $urn);
    //    error_log("   PUBROW = " . print_r($pubrow, true));
    $id = $pubrow['_GENI_IDENTIFYING_MEMBER_UID'];
    $m = new Member($id);
    $m->init_from_record($pubrow);
    $m->init_from_record($idrow[$urn]);
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


// List all clients
function ma_list_clients($ma_url, $signer)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $res = $client->list_clients();
  return $res;
}

// list all clients authorized by the member
function ma_list_authorized_clients($ma_url, $signer, $member_id)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $res = $client->list_authorized_clients($member_id);
  return $res;
}

// authorize a client
function ma_authorize_client($ma_url, $signer, $member_id, $client_urn,
			     $authorize_sense)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $res = $client->authorize_client($member_id, $client_urn, $authorize_sense);
  return $res;
}

// 
//CHAPI: Now an pseudo-alias for ma_lookup_members_by_identifying(...)[0]
function ma_lookup_member_id($ma_url, $signer, $member_id_key, $member_id_value)
{
  $chapi_member_id_key = _portalkey_to_attkey($member_id_key);
  $res = ma_lookup_members_by_identifying($ma_url, $signer, $chapi_member_id_key, $member_id_value);
  return $res; // it seems to want to return the list of members
}

// get the one member (or null) that matches the specified id
function ma_lookup_member_by_id($ma_url, $signer, $member_id)
{
  $res = ma_lookup_members_by_identifying($ma_url, $signer, 'MEMBER_UID', $member_id);
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
}

// get '_GENI_MEMBER_SSL_PUBLIC_KEY' (which means certificate)
function ma_lookup_certificate($ma_url, $signer, $member_id)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_id),
		   'filter'=>array('_GENI_MEMBER_SSL_PUBLIC_KEY'));
  $res = $client->lookup_public_member_info($client->creds(), 
					    $options);
  $ssh_keys = array_map(function($x) { return $x['_GENI_MEMBER_SSL_PUBLIC_KEY']; }, $res);
  return $ssh_keys;
}


// Lookup all details for all members whose ID's are specified
// details will be [memberid => attributes, ...]
// attributes is [at1=>v1, ...]
// where atN is one of DETAILS_PUBLIC, DETAILS_IDENT
function lookup_member_details($ma_url, $signer, $member_uuids)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $result = array();
  //  error_log("LMD : " . print_r($member_uuids, true));
  foreach ($member_uuids as $uid) {
    $pubdet = _lookup_public_member_details($client, $signer, $uid);
    //error_log("LMD ".print_r($uid, True)." public=".print_r($pubdet, True));
    $iddet = _lookup_identifying_member_details($client, $signer, $uid);
    //error_log("LMD ".print_r($uid, True)." identifying=".print_r($iddet, True));
    $alldet = array_merge($pubdet,$iddet);
    //$alldet = $pubdet;
    $attrs = array();
    foreach ($alldet as $k => $v) {
      $ak = _attkey_to_portalkey($k);
      $attrs[$ak] = $v;
      //error_log("LMD ".print_r($uid, True)." ".$k."(".$ak.") = ".print_r($v, True));
      // error_log("LMD attrs=".print_r($attrs, True));
    }
    $result[$uid] = $attrs;
    //error_log("LMD final".print_r($uid, True)." attrs=".print_r($attrs, True));
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

// lookup public details for one member
function _lookup_public_member_details($client, $signer, $uid)
{
  $r = _lookup_public_members_details($client, $signer, array($uid));
  if (sizeof($r)>0) {
    $urns = array_keys($r);
    $urn = $urns[0];
    return $r[$urn];
  } else {
    return array();
  }
}

function _lookup_public_members_details($client, $signer, $uid)
{
  global $DETAILS_PUBLIC;
  $options = array('match'=>array('MEMBER_UID'=>$uid),
		   'filter'=>$DETAILS_PUBLIC);
  $r = $client->lookup_public_member_info($client->creds(), 
					  $options);
  return $r;
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
  global $DETAILS_IDENTIFYING;
  //error_log( " _limd = " . print_r($uid, true));
  $r = $client->lookup_identifying_member_info($client->creds(),
					       array('match'=>array('MEMBER_UID'=>$uid),
						     'filter'=>$DETAILS_IDENTIFYING));
  if (sizeof($r)>0) {
    $urns = array_keys($r);
    $urn = $urns[0];
    return $r[$urn];
  } else {
    return array();
  }
}


// Lookup the display name for all member_ids in a given set of 
// rows, where the member_id is selected by given field name
// Do not include the given signer in the query but add in the response
// If there is no member other than the signer, don't make the query
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
  return $names_by_id;
}

// Lookup the 'display name' for all members whose ID's are specified
function lookup_member_names($ma_url, $signer, $member_uuids)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('MEMBER_UID'=>$member_uuids),
		   'filter'=>array('MEMBER_UID', 'MEMBER_USERNAME'));
  //error_log( " _lmns = " . print_r($member_uuids, true));
  $res = $client->lookup_public_member_info($client->creds(), $options);
  $ids = array();
  foreach($res as $member_urn => $member_info) {
    $member_uuid = $member_info['MEMBER_UID'];
    $member_username = $member_info['MEMBER_USERNAME'];
    $ids[$member_uuid] = $member_username;
  }
  return $ids;
}

// Lookup all members with given email
// Return dictionary email => [member_ids]*
function lookup_members_by_email($ma_url, $signer, $member_emails)
{
  $client = XMLRPCClient::get_client($ma_url, $signer);
  $options = array('match'=> array('MEMBER_EMAIL'=>$member_emails),
                   'filter'=>array('_GENI_IDENTIFYING_MEMBER_UID', 'MEMBER_EMAIL'));

  //error_log( " lmbe = " . print_r($member_emails, true));
  $res = $client->lookup_identifying_member_info($client->creds(), $options);
  $ret = array();
  foreach ($res	as $vals) {
    if (! $ret[$vals['MEMBER_EMAIL']]) {
      $ret[$vals['MEMBER_EMAIL']] = array();
    }
    $ret[$vals['MEMBER_EMAIL']][] = $vals['_GENI_IDENTIFYING_MEMBER_UID'];
  }
  return $ret;
}


function get_member_urn($ma_url, $signer, $id) {
  $cache = get_session_cached('member_urn');
  if (array_key_exists($id, $cache)) {
      return $cache[$id];
  } else {
    $client = XMLRPCClient::get_client($ma_url, $signer);
    $options = array('match'=>array('MEMBER_UID'=>$id),
		     'filter'=>array('MEMBER_URN'));
    $r = $client->lookup_public_member_info($client->creds(), 
					    $options);

    if (sizeof($r)>0) {
      $urns = array_keys($r);
      $urn = $urns[0];
    } else {
      $urn = null;  // cache failures
    }
    $cache[$id] = $urn;
    set_session_cached('member_urn', $cache);
    return $urn;
  }
}

?>
