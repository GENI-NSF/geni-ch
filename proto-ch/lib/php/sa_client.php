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

// Client-side interface to GENI Clearinghouse Slice Authority (SA)
//
// Consists of these methods:
//   get_slice_credential(slice_id, user_id)
//   slice_id <= create_slice(project_id, project_name, slice_name, owner_id);
//   slice_ids <= lookup_slices(project_id);
//   slice_details <= lookup_slice(slice_id);
//   slice_details <= lookup_slice_by_urn(slice_urn);
//   renew_slice(slice_id, expiration, owner_id);
//   get_slice_members(sa_url, slice_id, role=null) // null => Any
//   get_slices_for_member(sa_url, member_id, is_member, role=null)
//   lookup_slice_details(sa_url, slice_uuids)
//   get_slices_for_projects(sa_url, project_uuids, allow_expired=false)
//   modify_slice_membership(sa_url, slice_id, 
//        members_to_add, members_to_change_role, members_to_remove)
//   add_slice_member(sa_url, project_id, member_id, role)
//   remove_slice_member(sa_url, slice_id, member_id)
//   change_slice_member_role(sa_url, slice_id, member_id, role)

require_once('sa_constants.php');
require_once('chapi.php');
require_once 'ma_client.php';

/* Create a slice credential for given SLICE ID and user */
function get_slice_credential($sa_url, $signer, $slice_id, $cert=NULL)
{
  $slice_urn = get_slice_urn($sa_url, $signer, $slide_id);

  $signer_cert = $signer->certificate();
  $signer_key = $signer->privateKey();
  if (is_null($cert)) {
    $cert = $signer_cert;
  }
  if (! isset($cert) || is_null($cert) || $cert == "") {
    error_log("Cannot get_slice_cred without a user cert");
    throw new Exception("Cannot get_slice_cred without a user cert");
  }
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array();

  $result = $client->get_credentials($slice_urn, $client->get_credentials(), $options);
  return $result; //MIK: was $result['slice_credential'];
}

/* Create a new slice record in database, return slice_id */
function create_slice($sa_url, $signer, $project_id, $project_name, $slice_name,
                      $owner_id, $description='')
{
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('SLICE_NAME' => $slice_name,
		   'SLICE_DESCRIPTION' => $description,
		   'SLICE_EMAIL' => null,       // MIK: required for the api, but not passed through (controller was null)
		   //'SLICE_EXPIRATION' => '',  // MIK: not supplied here
		   //// are the following supported/allowed? MIK
		   'PROJECT_URN' => $project_id,  // MIK - project_ids are all really URNs
		   'PROJECT_NAME' => $project_name,
		   'OWNER_URN' => $owner_id);
  $slice = $client->create_slice($slice_id, $client->get_credentials(), $options); 
  // CHAPI: TODO reformat return arguments
  return $slice;
}

/* Lookup slice ids for given project */
function lookup_slice_ids($sa_url, $signer, $project_id)
{
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('match' => array('PROJECT_URN' => $project_id),
		   'filter' => array('SLICE_UID'));
  $slices = $client->lookup_slices($client->get_credentials(), $options);

  return array_map(function($x) { return $x['SLICE_UID']; }, $slices);
}

/* Lookup slice ids for given project and owner */
/* function lookup_slice_ids_by_project_and_owner($sa_url, $project_id, $owner_id) */
/* { */
/*   $lookup_slice_ids_message['operation'] = 'lookup_slice_ids'; */
/*   $lookup_slice_ids_message[SA_ARGUMENT::PROJECT_ID] = $project_id; */
/*   $lookup_slice_ids_message[SA_ARGUMENT::OWNER_ID] = $owner_id; */
/*   $slice_ids = put_message($sa_url, $lookup_slice_ids_message); */
/*   return $slice_ids; */
/* } */

/* Lookup slice ids for given owner */
/* function lookup_slice_ids_by_owner($sa_url, $owner_id) */
/* { */
/*   $lookup_slice_ids_message['operation'] = 'lookup_slice_ids'; */
/*   $lookup_slice_ids_message[SA_ARGUMENT::OWNER_ID] = $owner_id; */
/*   $slice_ids = put_message($sa_url, $lookup_slice_ids_message); */
/*   return $slice_ids; */
/* } */

/* lookup slice ids by slice name, project ID */
/* function lookup_slices_by_project_and_name($sa_url, $project_id, $slice_name) */
/* { */
/*   $lookup_slice_ids_message['operation'] = 'lookup_slice_ids'; */
/*   $lookup_slice_ids_message[SA_ARGUMENT::PROJECT_ID] = $project_id; */
/*   $lookup_slice_ids_message[SA_ARGUMENT::SLICE_NAME] = $slice_name; */
/*   $slice = put_message($sa_url, $lookup_slice_ids_message); */
/*   return $slice_ids; */
/* } */

/* lookup a set of slices by name, project_id, member_id */
/* That is, the set of slices for which this member_id is a member */
function lookup_slices($sa_url, $signer, $project_id, $member_id)  // project_id= project_urn, member_id=member_urn
{
  $member_urn = get_member_urn(sa_to_ma_url($sa_url), $signer, $member_id);
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array(
		   'match' => array('PROJECT_URN' => $project_id),
		   'filter' => array('SLICE_UID')
		   );
  $slices = $client->lookup_slices_for_member($member_urn, $client->get_credentials(), $options);
  
  $result = $projects[$project_urn] = array_map(function($x) { return $x['SLICE_UID']; }, $slices);

  return $result;
}

/* lookup details of slice of given id */
// Return array(id, name, project_id, expiration, owner_id, urn)
function lookup_slice($sa_url, $signer, $slice_id)
{
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('match' => array('SLICE_UID' => $slice_id),
		   // 'filter' => array('SLICE_URN')  // MIK: do we get everything if no filter specified?
		   );
  $slices = $client->lookup_slices($client->get_credentials(), $options);
  $slice = $slices[0];
  
  return array($slice['SLICE_UID'],
	       $slice['SLICE_NAME'],
	       $slice['PROJECT_URN'],  // UID?
	       $slice['SLICE_EXPIRATION'],
	       $slice['OWNER_URN'],    // UID?
	       $slice['SLICE_URN']);
}

/* lookup details of slice of given slice URN */
// Return array(id, name, project_id, expiration, owner_id, urn)
function lookup_slice_by_urn($sa_url, $signer, $slice_urn)
{
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('match' => array('SLICE_URN' => $slice_urn),
		   // 'filter' => array('SLICE_URN')  // MIK: do we get everything if no filter specified?
		   );
  $slices = $client->lookup_slices($client->get_credentials(), $options);
  $slice = $slices[0];
  
  return array($slice['SLICE_UID'],
	       $slice['SLICE_NAME'],
	       $slice['PROJECT_URN'],  // UID?
	       $slice['SLICE_EXPIRATION'],
	       $slice['OWNER_URN'],    // UID?
	       $slice['SLICE_URN']);
}

// FIXME: lookup_slice_details_by_ids($sa_url, $slice_ids_list)
// FIXME: lookup_slices_project_member($sa_url, $project_id=null, $member_id, $is_member, $role=null)

/* Renew slice of given id */
function renew_slice($sa_url, $signer, $slice_id, $expiration)
{
  $slice_urn = get_slice_urn($sa_url, $signer, $slice_id);

  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('update' => array('SLICE_EXPIRATION' => $expiration),
		   );
  $client->update_slice($slice_urn, $client->get_credentials(), $options);
  // no return
}

// Modify slice membership according to given lists to add/change_role/remove
// $members_to_add and $members_to_change role are both
//     dictionaries of {member_id => role, ....}
// $members_to_delete is a list of member_ids
function modify_slice_membership($sa_url, $signer, $slice_id, 
				 $members_to_add, 
				 $members_to_change_role, 
				 $members_to_remove)
{
  $slice_urn = get_slice_urn($sa_url, $signer, $slice_id);

  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('members_to_add' => $members_to_add,
		   'members_to_remove' => $members_to_remove,
		   'members_to_change' => $members_to_change,
		   );
  $client->modify_slice_membership($slice_urn, $client->get_credentials(), $options);
}

// Add a member of given role to given slice
function add_slice_member($sa_url, $signer, $slice_id, $member_id, $role)
{
  $member_roles = array($member_id => $role);
  $result = modify_slice_membership($sa_url, $signer, $slice_id, 
				    $member_roles, array(), array());
  return $result;
}

// Remove a member from given slice 
function remove_slice_member($sa_url, $signer, $slice_id, $member_id)
{
  $member_to_remove = array($member_id);
  $result = modify_slice_membership($sa_url, $signer, $slice_id, 
				    array(), array(), $member_to_remove);
  return $result;
}

// Change role of given member in given slice
function change_slice_member_role($sa_url, $signer, $slice_id, $member_id, $role)
{
  $member_roles = array($member_id => $role);
  $result = modify_slice_membership($sa_url, $signer, $slice_id, 
				    array(), $member_roles, array());
  return $result;
}

// Return list of member ID's and roles associated with given slice
// If role is provided, filter to members of given role
function get_slice_members($sa_url, $signer, $slice_id, $role=null)
{
  $slice_urn = get_slice_urn($sa_url, $signer, $slice_id);

  $client = new XMLRPCClient($sa_url, $signer);
  $options = array();
  if (! is_null($role)) {
    $options['match'] = array('SLICE_ROLE' => $role);
  }
  $result = $client->lookup_slice_members($slice_urn, $client->get_credentials(), $options);
  return $results;  // CHAPI: TODO: reformat output to match old
}

// Return list of slice_id's, member ID's and roles associated with slice of a given project
// If role is provided, filter to members of given role
// CHAPI: I take this to mean the return is [[slice1 mem1 role1] [slice1 mem2 role2] [slice2 mem3 role1] ...], 
// rather than a map/tree of any sort

// slice-> PROJECT_URN
// 
function get_slice_members_for_project($sa_url, $signer, $project_id, $role=null)
{
  $client = new XMLRPCClient($sa_url, $signer);

  // get all slices of project
  $options = array('match' => array('PROJECT_UID'=>$slice_uid));
  $tuples = $client->lookup_slices($client->get_credentials(), $options);

  $results = array();
  $moptions = array();
  if (!is_null($role)) {
    $moptions['match'] = array('SLICE_ROLE'=>$role);
  }
  foreach ($tuples as $stup) {
    $surn = $stup['SLICE_URN'];
    $sid = $stup['SLICE_UID'];
    
    $mems = $client->lookup_slice_members($surn, $client->get_credentials(), $moptions);
    foreach ($mems as $mtup) {
      $results[] = array($sid, $mtup['SLICE_MEMBER'], $mtup['SLICE_ROLE']);
    }
  }
  return $result;
}

// Return list of slice ID's and Roles for given member_id for slices to which member belongs
// If is_member is true, return slices for which member is a member
// If is_member is false, return slices for which member is NOT a member
// If role is provided, filter on slices 
//    for which member has given role (is_member = true)
//    for which member does NOT have given role (is_member = false)
// FIXME: optional project_id to constrain to a given project?
// CHAPI: okay (except for is_member=false)
function get_slices_for_member($sa_url, $signer, $member_id, $is_member, $role=null)
{
  $member_urn = get_member_urn(sa_to_ma_url($sa_url), $signer, $member_id);
  $client = new XMLRPCClient($sa_url, $signer);

  if ($is_member) {
    $options = array('_dummy' => null);
    if (!is_null($role)) {
      $options = array('match'=>array('SLICE_ROLE'=>$role));
    }
    $results = $client->lookup_slices_for_member($member_urn, $client->get_credentials(), $options);
  } else {
    // CHAPI: TODO: implement is_member = FALSE
    error_log("get_slices_for_member using is_member=false is unimplemented.");
    return array();
  }

  // Convert columns from 'external' to 'internal' format
  $converted_results = array();
  foreach($results as $row) {
    $row[SA_SLICE_MEMBER_TABLE_FIELDNAME::SLICE_ID] = $row['SLICE_UID'];
    $converted_results[] = $row;
  }
  $results = $converted_results;
  //  error_log("GSFM.RESULTS = " . print_r($results, true));

  return $results;
}

function lookup_slice_details($sa_url, $signer, $slice_uuids)
{
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('match' => array('SLICE_UID'=>$slice_uuids));
  $result = $client->lookup_slices($client->get_credentials(), $options);
  $converted_slices = array();
  foreach ($result as $slice_uuid => $slice) {
    $converted_slices[$slice_uuid] = convert_slice_to_internal($slice);
  }
  $result = $converted_slices;
  //  error_log("LSD.result = " . print_r($result, true));
  return $result;
}

// Convert slice details from external (CH API compliant) names
// to internal (database field) names
function convert_slice_to_internal($slice)
{
  return array(
	       SA_SLICE_TABLE_FIELDNAME::SLICE_ID => $slice['SLICE_UID'],
	       SA_SLICE_TABLE_FIELDNAME::SLICE_NAME =>  $slice['SLICE_NAME'],
	       SA_SLICE_TABLE_FIELDNAME::PROJECT_ID => 
	       $slice['_GENI_PROJECT_UID'],
	       SA_SLICE_TABLE_FIELDNAME::EXPIRATION => $slice['SLICE_EXPIRATION'],
	       SA_SLICE_TABLE_FIELDNAME::OWNER_ID => 
	       $slice['_GENI_SLICE_OWNER'],
	       SA_SLICE_TABLE_FIELDNAME::SLICE_URN => $slice['SLICE_URN'],
	       SA_SLICE_TABLE_FIELDNAME::SLICE_EMAIL =>
	       $slice['_GENI_SLICE_EMAIL'],
	       SA_SLICE_TABLE_FIELDNAME::EXPIRED => $slice['SLICE_EXPIRED'],
	       SA_SLICE_TABLE_FIELDNAME::SLICE_DESCRIPTION => $slice['SLICE_DESCRIPTION']);

}

// Return a dictionary of the list of slices (details) for a give
// set of project uuids, indexed by project UUID
// e.g.. [p1 => [s1_details, s2_details....], p2 => [s3_details, s4_details...]
// Optinonally, allow expired slices (default=false)
function get_slices_for_projects($sa_url, $signer, $project_uuids, $allow_expired=false)
{
  $client = new XMLRPCClient($sa_url, $signer);
  $projects = array();
  foreach($project_uuids as $project_uuid) { 
    $projects[$project_uuid] = array();
  }
  //  error_log("GSFP.PROJECT_UUIDS = " . print_r($project_uuids, true));
  $options = array('match' => array('_GENI_PROJECT_UID' => $project_uuids));
  $slices = $client->lookup_slices($client->get_credentials(), $options);
  $converted_slices = array();
  foreach( $slices as $slice) {
    $converted_slices[] = convert_slice_to_internal($slice);
  }
  $slices = $converted_slices;
  //  error_log("GSFP.SLICES = " . print_r($slices, true));
  foreach($slices as $slice_urn => $slice) {
    $project_uid = $slice[SA_SLICE_TABLE_FIELDNAME::PROJECT_ID];
    $projects[$project_uid][] = $slice;
  }

  // Convert from external to internal field names
  //  error_log("GSFP.PROJECTS = " . print_r($projects, true));
// return map of (project_uid_1 => (slice_data_1, ...), 
//                project_uid_2 => (slice_data_2, ..), ..)
  return $projects;  
}

// find the slice URN, given a slice UID
function get_slice_urn($sa_url, $signer, $slice_uid) {
  $client = new XMLRPCClient($sa_url, $signer);
  $options = array('match' => array('SLICE_UID'=>$slice_uid),
		   'filter' => array('SLICE_URN'));
  $result = $client->lookup_slices($client->get_credentials(), $options);
  return $result[0]['SLICE_URN'];
}

// CHAPI: convert a SA URL into a MA url
function sa_to_ma_url($sa_url) {
  return preg_replace("/SA$/", "MA", $sa_url);
}

?>
