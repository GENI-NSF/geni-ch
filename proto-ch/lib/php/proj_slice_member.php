<?php
//----------------------------------------------------------------------
// Copyright (c) 2012 Raytheon BBN Technologies
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

function get_project_slice_member_info($sa_url, $ma_url, $user, $allow_expired=False)
{
  $member_ids = array();
  $slice_ids = array();
  $slice_objects = array();
  $project_objects = array();
  $member_objects = array();
  $project_slice_map = array();
  $project_activeslice_map = array();


  // This is all project IDs the member belongs to, even expired
  $projects = get_projects_for_member($sa_url, $user, $user->account_id, true);
  if (count($projects) > 0) {
    // These are the details of these projects 
    $project_objects = lookup_project_details($sa_url, $user, $projects);

    // We get back all the projects. But optionally filter out expired projects.
    if(!$allow_expired) {
      $unexpired_projects = array();
      $unexpired_project_objects = array();
      $now = new DateTime();
      foreach($project_objects as $project) {
        $project_id = $project[PA_PROJECT_TABLE_FIELDNAME::PROJECT_ID];
	$project_expired = $project[PA_PROJECT_TABLE_FIELDNAME::EXPIRED];
	$project_name = $project[PA_PROJECT_TABLE_FIELDNAME::PROJECT_NAME];
	//	error_log("PEXP = " . $project_id . " " . $project_name . 
	//      " " . $project_expired);
	if ($project_expired == 't')
	  continue;
	$unexpired_project_objects[] = $project;
	$unexpired_projects[] = $project_id;
      }
      $projects = $unexpired_projects;
      $project_objects = $unexpired_project_objects;
    }

    // At this point, $projects and $project_objects have all
    // the projects we're interested in: expired or not


    // Get all slices of which user is a member (expired or not) 
    $slice_member_role_ids = 
      get_slices_for_member($sa_url, $user, $user->account_id, True);
    $slice_member_ids = array();
    foreach($slice_member_role_ids as $slice_member_role_id) {
      $slice_member_id = 
	$slice_member_role_id[SA_SLICE_MEMBER_TABLE_FIELDNAME::SLICE_ID];
      $slice_member_ids[] = $slice_member_id;
    }

    // $slice_emmber_ids is the ID's of slices to which the member belongs

    // This is indexed by project_id, containing an array of slice data
    // CHAPI: this doesn't generally work any more, since non-members aren't allowed
    // to get details for slices they aren't members of
    //$slice_data = get_slices_for_projects($sa_url, $user, $projects, $allow_expired);
    $slice_data = get_slices_in_projects($sa_url, $user, $slice_member_ids, $projects, $allow_expired);
    

    //error_log("SLICE_MEMBER_IDS = " . print_r($slice_member_ids, true));
    //error_log("SLICE_DATA =  = " . print_r($slice_data, true));
    //error_log("PROJECTS = " . print_r($projects, true));
    foreach ($project_objects as $project) {
      $project_id = $project[PA_PROJECT_TABLE_FIELDNAME::PROJECT_ID];
      $proj_lead_id = $project[PA_PROJECT_TABLE_FIELDNAME::LEAD_ID];
      $proj_slices = $slice_data[$project_id];
      $member_ids[] = $proj_lead_id;
      $proj_slice_ids = array();
      $proj_activeslice_ids = array();
      foreach($proj_slices as $proj_slice) {
	$proj_slice_id = $proj_slice[SA_SLICE_TABLE_FIELDNAME::SLICE_ID];
	$proj_slice_id_expired = $proj_slice[SA_SLICE_TABLE_FIELDNAME::EXPIRED];
	if (!in_array($proj_slice_id, $slice_member_ids)) continue;
	$proj_slice_ids[] = $proj_slice_id;
	//error_log("slice id = ". $proj_slice_id . " expired = " . $proj_slice_id_expired);
	if (!$proj_slice_id_expired) {		
	  //error_log("Adding active slice to list ....");
	  $proj_activeslice_ids[] = $proj_slice_id;		
	}
      }
      //	$proj_slice_ids = lookup_slice_ids($sa_url, $user, $project_id);  
      $project_slice_map[ $project_id ] = $proj_slice_ids;
      $project_activeslice_map[ $project_id ] = $proj_activeslice_ids;
      //error_log("GPSMI: project ".$project_id." ids = ".print_r($proj_activeslice_ids,true));
      $slice_ids = array_merge( $slice_ids, $proj_slice_ids ); // is this ok
    }	      
  }

  // $slice_ids is all ID's of slices of projects to which user belongs
  // BUT NOT NECESSARILY that the member belongs to the slices themselves

  // This should filter out the slices by those who are expired
  // And those to whom the member doesn't belong
  if (count($slice_ids) > 0) {
    $slice_objects = array();
     $all_slice_objects = lookup_slice_details($sa_url, $user, $slice_ids);
     foreach ($all_slice_objects as $slice) {

        $slice_id = $slice[SA_SLICE_TABLE_FIELDNAME::SLICE_ID]; 

       // Don't include slices who don't belong to any project 
	if(!in_array($slice_id, $slice_member_ids)) continue;

        $owner_id = $slice[SA_SLICE_TABLE_FIELDNAME::OWNER_ID]; 
	if(!in_array($owner_id, $member_ids)) {
	  $member_ids[] = $owner_id;
	}

	// Optionally filter out expired slices
        $expired = $slice[SA_SLICE_TABLE_FIELDNAME::EXPIRED]; 
	//	error_log("EXP = " . print_r($expired, true) . " AEXP = " . print_r($allow_expired, true) . " SLICE = " . print_r($slice, true));
	if($expired != 't' || $allow_expired) 
	  $slice_objects[$slice_id] = $slice;

     }          
  }    
  if (count($member_ids) > 0) {
     $member_objects = lookup_member_details($ma_url, $user, $member_ids);     
  }


  //  error_log("SIDS = " . print_r($slice_ids, true));
  //  error_log("MIDS = " . print_r($member_ids, true));
  //  error_log("SMIDS = " . print_r($slice_member_ids, true));
  //  foreach($project_objects as $po) { error_log("PO = " . print_r($po, true)); }
  //  foreach($slice_objects as $so) { error_log("SO = " . print_r($so, true)); }


  // At this point, we should have 
  // project_objects has all the projects to which the member belongs 
  //    expired or not by request
  // slice_objects has all the slices to which the member belongs
  //    expired or not by request
  // member_objects
  //    all the members who are leads of slices or projects in previous lists
  return array( $project_objects, $slice_objects, $member_objects, $project_slice_map, $project_activeslice_map );
}


// for a given slice, find all of the members on the slice and 
// return as a list of GeniUser()
function get_all_members_of_slice_as_users( $sa_url, $ma_url, $user, $slice_id) {
   // Get other users on this project
   $members = get_slice_members($sa_url, $user, $slice_id);
   //error_log("Return from get_slice_members = " . print_r($members, TRUE));
   $member_uuids = array();
   foreach ($members as $member) {
	$member_id = $member[MA_ARGUMENT::MEMBER_ID];
	// In Future consider FILTER by ROLE?
	//	$role_id = $member[ 'role' ]; // FIND VARIABLE TO REPLACE
	$member_uuids[] = $member_id;
   }

   $slice_members = lookup_member_details($ma_url, $user, $member_uuids );
   //error_log("Slice members = " . print_r($slice_members, TRUE));

   $slice_users = array();
   foreach ($slice_members as $member_id => $slice_member) {
	// initialize members
	$member = new Member();
	$member->init_from_record($slice_member);
	//error_log("Member = " . print_r($member, TRUE));	
	// now as users 
	$slice_user = new GeniUser();     
   	$slice_user->init_from_member($member);
	//	error_log("Slice user = " . print_r($slice_user, TRUE));
 	$identity = geni_load_identity_by_eppn($slice_user->eppn);
     	$slice_user->init_from_identity($identity);
 	$slice_users[] = $slice_user;
   }

   //error_log("Slice users = " . print_r($slice_users, TRUE));
   return $slice_users;
}



?>

