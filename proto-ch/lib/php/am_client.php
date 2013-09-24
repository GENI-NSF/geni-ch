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

// Routines for clients speaking to an aggregate maanger

require_once('file_utils.php');
require_once 'geni_syslog.php';
require_once 'logging_client.php';
require_once 'sr_client.php';
require_once 'portal.php';
require_once("pa_client.php");
require_once("pa_constants.php");
require_once('cert_utils.php');

function log_action($op, $user, $agg, $slice = NULL, $rspec = NULL)
{
  $log_url = get_first_service_of_type(SR_SERVICE_TYPE::LOGGING_SERVICE);
  $user_id = $user->account_id;
  if (! is_array($agg)) {
    $aggs[] = $agg;
  } else {
    $aggs = $agg;
  }
  foreach ($aggs as $am) {
    $attributes['aggregate'] = $am;
    $msg = "$op at $am";
    if ($slice) {
      $msg .= " on $slice";
      $attributes['slice'] = $slice;
    }
    if ($rspec) {
      $attributes['rspec'] = $rspec;
    }
    $result = log_event($log_url, Portal::getInstance(), $msg, $attributes, $user_id);
  }
}

/*
 * Writes the user's ssh keys to files for use in the omni config file.
 *
 * Returns an array of temporary filenames. The caller is responsible
 * for deleting (unlink) these files.
 */
function write_ssh_keys($for_user, $as_user)
{
  $result = array();

  $ma_url = get_first_service_of_type(SR_SERVICE_TYPE::MEMBER_AUTHORITY);
  $ssh_keys = lookup_public_ssh_keys($ma_url, $as_user, $for_user->account_id);

  foreach ($ssh_keys as $key_info)
    {
      $key = $key_info['public_key'];
      $tmp_file = writeDataToTempFile($key, $for_user->username . "-ssh-key-");
      $result[] = $tmp_file;
    }
  return $result;
}

function get_template_omni_config($user, $version, $default_project=null)
{
  $legal_versions = array("2.3.1");
  if (! in_array($version, $legal_versions)) {
    /* If $version is not understood, default to omni 2.3.1. */
    $version = "2.3.1";
  }

    /* Create OMNI config file */
    $username = $user->username;
    $urn = $user->urn();
    // Get the authority from the user's URN
    parse_urn($urn, $authority, $type, $name);

    // Add shortcuts for all known AMs?
    // Note this makes the config long in the extreme case....
    require_once("sr_client.php");
    require_once("sr_constants.php");
    $ams = get_services_of_type(SR_SERVICE_TYPE::AGGREGATE_MANAGER);
    $nicknames = "";
    foreach ($ams as $am) {
      $name = $am[SR_TABLE_FIELDNAME::SERVICE_NAME];
      $url = $am[SR_TABLE_FIELDNAME::SERVICE_URL];
      if (! isset($name) || is_null($name) || trim($name) == '') {
        continue;
      }
      // skip AMs running on localhost as they aren't accessible anywhere else
      if (strpos($url, '://localhost') !== false ) {
        continue;
      }

      $name = str_replace(' ', '-', $name);
      $name = str_replace(',', '', $name);
      $name = str_replace('=', '', $name);
      $name = strtolower($name);
      $nicknames .= "$name=,$url\n";
    }

    $pgchs = get_services_of_type(SR_SERVICE_TYPE::PGCH);
    if (count( $pgchs ) != 1) {
          error_log("am_client must have exactly one PGCH service defined to generate an omni_config");
	  return("Should be exactly one PGCH url.");
    } else {
        $pgch = $pgchs[0];
      	$PGCH_URL = $pgch[SR_TABLE_FIELDNAME::SERVICE_URL];	
    }

    $omni_config = '# This omni configuration file is for use with omni version ';
    if ($version == '2.3.1') {
      $omni_config .= '2.3.1 or higher';
    }
    $omni_config .= "\n";
    $omni_config .= "[omni]\n"
      . "default_cf = portal\n"
      . "# 'users' is a comma separated list of users which should be added to a slice.\n"
      . "# Each user is defined in a separate section below.\n"
      . "users = $username\n";

    if ($version == '2.3.1') {
     $omni_config = $omni_config		
      . "# 'default_project' is the name of the project that will be assumed\n"
      . "# unless '--project' is specified on the command line.\n"
      . "# Uncomment only one of the following lines if you want to use this feature\n";

    if (! isset($sa_url)) {
       $sa_url = get_first_service_of_type(SR_SERVICE_TYPE::SLICE_AUTHORITY);	
    }
    $projects = get_projects_for_member($sa_url, $user, $user->account_id, true);	
    if (count($projects) > 0 && is_null($default_project)) {
      $p0 = $projects[0];
      $default_project = $p0[PA_PROJECT_TABLE_FIELDNAME::PROJECT_NAME];
    }
    foreach ($projects as $project_id) {
      $project = lookup_project($sa_url, $user, $project_id);
      $proj_name = $project[PA_PROJECT_TABLE_FIELDNAME::PROJECT_NAME];
      if ($proj_name == $default_project) {
        $omni_config .= "default_project = $proj_name\n";
      } else {
        $omni_config .= "#default_project = $proj_name\n";
      }
    }
    }
    $omni_config = $omni_config
      . "\n"
      . "[portal]\n";

    if ($version == "2.3.1") {
      $omni_config .= "type = pgch\n";
    }

    $omni_config = $omni_config
      . "authority=$authority\n"
      . "ch = $PGCH_URL\n"
      . "sa = $PGCH_URL\n"
      . "cert = /PATH/TO/YOUR/CERTIFICATE/AS/DOWNLOADED/FROM/PORTAL/geni-$username.pem\n"
      . "key = /PATH/TO/YOUR/CERTIFICATE/AS/DOWNLOADED/FROM/PORTAL/geni-$username.pem\n"
      . "\n"
      . "[$username]\n"
      . "urn = $urn\n"
      . "# 'keys' is a comma separated list of ssh public keys which should be added to this user's account.\n"
      . "keys = /PATH/TO/SSH/PUBLIC/KEY.pub\n";

    $omni_config = $omni_config
      . "\n"
      . "[aggregate_nicknames]\n"
      . $nicknames;

    return $omni_config;
}

/**
 * Create a temporary omni config file for $user and return the file
 * name.
 *
 * N.B. the caller is responsible for removing the file (via unlink()).
 */
function write_omni_config($user)
{
    $username = $user->username;
    $urn = $user->urn();
    // Get the authority from the user's URN
    parse_urn($urn, $authority, $type, $name);

    /* Write key and credential files. */
    $cert = $user->certificate();
    $cert_file = writeDataToTempFile($cert, "$username-cert-");
    $private_key = $user->privateKey();
    $key_file = writeDataToTempFile($private_key, "$username-key-");

    /* Write ssh keys to tmp files. */
    $ssh_key_files = write_ssh_keys($user, $user);
    $all_key_files = implode(',', $ssh_key_files);

    /* Create OMNI config file */
    $omni_config = "[omni]\n"
      . "default_cf = my_gcf\n"
      . "users = $username\n"
      . "[my_gcf]\n"
      . "type=gcf\n"
      . "authority=$authority\n"
      . "ch=https://localhost:8000\n"
      . "cert=$cert_file\n"
      . "key=$key_file\n"
      . "[$username]\n"
      . "urn=$urn\n"
      . "keys=$all_key_files\n";

    $omni_file = writeDataToTempFile($omni_config, "$username-omni-");

    $result = array($omni_file, $cert_file, $key_file);
    foreach ($ssh_key_files as $f) {
      $result[] = $f;
    }
    return $result;
}

// Generic invocation of omni function 
// Args:
//    $am_url: URL of AM to which to connect
//    $user : Structure with user information (for creating temporary files)
//    $args: list of arguments (including the method itself) included
function invoke_omni_function($am_url, $user, $args, $slice_users=array())
{
    $username = $user->username;
    $urn = $user->urn();
    // Get the authority from the user's URN
    parse_urn($urn, $authority, $type, $name);
    
    $aggregates = "aggregates=";
    $first=True;
    if (is_array($am_url)){
      foreach ($am_url as $single){
	if (! isset($single) || is_null($single) || $single == '') {
	  error_log("am_client cannot invoke Omni with invalid AM URL");
	  return("Invalid AM URL");
	}
	if ($first){
	  $first=False;
	} else {
	  $aggregates = $aggregates.", ";	  
	}
	$aggregates = $aggregates.$single;
      }
      $aggregates = $aggregates."\n";
    }elseif (! isset($am_url) || is_null($am_url) || $am_url == '') {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }

    /* Write key and credential files */
    $cert = $user->certificate();
    $private_key = $user->privateKey();
    $tmp_version_cache = tempnam(sys_get_temp_dir(),
            'omniVersionCache');

    $cert_file = writeDataToTempFile($cert, "$username-cert-");
    $key_file = writeDataToTempFile($private_key, "$username-key-");

    $slice_users = $slice_users + array($user);
    $username_array = array();
    foreach ($slice_users as $slice_user){
    	   $username_array[] = $slice_user->username;
    }

    /* Create OMNI config file */
    $omni_config = "[omni]\n"
      . "default_cf = my_gcf\n"
      . "users = "
      . implode(", ", $username_array)
      . "\n";
    if (is_array($am_url)){
      $omni_config = $omni_config.$aggregates."\n";
    }
    $omni_config = $omni_config
      . "[my_gcf]\n"
      . "type=gcf\n"
      . "authority=$authority\n"
      . "ch=https://localhost:8000\n"
      . "cert=$cert_file\n"
      . "key=$key_file\n";

    $all_ssh_key_files = array();
    foreach ($slice_users as $slice_user){
       $slice_username = $slice_user->username;
       $slice_urn = $slice_user->urn();	
       $ssh_key_files = write_ssh_keys($slice_user, $user);
       $all_ssh_key_files = $all_ssh_key_files + $ssh_key_files;
       $all_key_files = implode(',', $ssh_key_files);
       $omni_config = $omni_config
             . "[$slice_username]\n"
             . "urn=$slice_urn\n"
      	     . "keys=$all_key_files\n";
    }

    $omni_file = writeDataToTempFile($omni_config, "$username-omni-ini-");

    /* Call OMNI */
    global $portal_gcf_dir;

    $omni_log_file = tempnam(sys_get_temp_dir(), $username . "-omni-log-");
    /*    $cmd_array = array($portal_gcf_dir . '/src/omni.py', */
    $cmd_array = array($portal_gcf_dir . '/src/omni_php.py',
		       '-c',
		       $omni_file,
		       '-l',
		       $portal_gcf_dir . '/src/logging.conf',
		       '--logoutput', $omni_log_file,
		       '--api-version',
		       '2',
            "--GetVersionCacheName",
            $tmp_version_cache);

    if (!is_array($am_url)){
      $cmd_array[]='-a';
      $cmd_array[]=$am_url;
    }

    for($i = 0; $i < count($args); $i++) {
      $cmd_array[] = $args[$i];
    }
    $command = implode(" ", $cmd_array);

     error_log("am_client invoke_omni_function COMMAND = " . $command);
     $handle = popen($command . " 2>&1", "r");
     $output= '';
     $read = fread($handle, 1024);
     while($read != null) {
       if ($read != null)
	 $output = $output . $read;
       $read = fread($handle, 1024);
     }
     pclose($handle);
  
     unlink($cert_file);
     unlink($key_file);
     unlink($omni_file);
     unlink($tmp_version_cache);
     foreach ($all_ssh_key_files as $tmpfile) {
       unlink($tmpfile);
     }

     $output2 = json_decode($output, True);
     if (is_null($output2)) {
       error_log("am_client invoke_omni_function:"
               . "JSON result is not parseable: \"$output\"");
       // this is probably a traceback from python
       // return it as a string
       return $output;
     }
     return $output2;
}

// Get version of AM API at given AM
function get_version($am_url, $user)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  $member_id = $user->account_id;
  $msg = "User $member_id calling GetVersion at $am_url";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  log_action("GetVersion", $user, $am_url);
  $args = array('getversion');
  $output = invoke_omni_function($am_url, $user, $args);
  return $output;
}


// List resources available at an aggregate
function list_resources($am_url, $user)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  $member_id = $user->account_id;
  $msg = "User $member_id calling ListResources at $am_url";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  log_action("ListResources", $user, $am_url);
  $args = array('-t', 'GENI', '3', 'listresources');
  $output = invoke_omni_function($am_url, $user, $args);
  return $output;
}

// list resources at an AM
function list_resources_on_slice($am_url, $user, $slice_credential, $slice_urn)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  if (! isset($slice_credential) || is_null($slice_credential) || $slice_credential == '') {
    error_log("am_client cannot act on a slice without a credential");
    return("Missing slice credential");
  }

  $member_id = $user->account_id;
  $msg = "User $member_id calling ListResources at $am_url on $slice_urn";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  log_action("ListResources", $user, $am_url, $slice_urn);
  $slice_credential_filename = writeDataToTempFile($slice_credential, $user->username . "-cred-");
  $args = array("--slicecredfile",
		$slice_credential_filename,
		'-t',
		'GENI',
		'3',
		'listresources',
		$slice_urn);
  $output = invoke_omni_function($am_url, $user, $args);
  unlink($slice_credential_filename);
  return $output;
}


// renewsliver at an AM
function renew_sliver($am_url, $user, $slice_credential, $slice_urn, $time)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  if (! isset($slice_credential) || is_null($slice_credential) || $slice_credential == '') {
    error_log("am_client cannot act on a slice without a credential");
    return("Missing slice credential");
  }

  $member_id = $user->account_id;
  $msg = "User $member_id calling RenewSliver at $am_url on $slice_urn";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  log_action("RenewSliver", $user, $am_url, $slice_urn);
  $slice_credential_filename = writeDataToTempFile($slice_credential, $user->username . "-cred-");
  $args = array("--slicecredfile",
		$slice_credential_filename,
		'renewsliver',
		$slice_urn,
		$time);
  $output = invoke_omni_function($am_url, $user, $args);
  // FIXME: Note that this AM still has resources
  unlink($slice_credential_filename);
  return $output;
}


// Create a sliver on a given AM with given rspec
function create_sliver($am_url, $user, $slice_users, $slice_credential, $slice_urn,
                       $rspec_filename)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  if (! isset($slice_credential) || is_null($slice_credential) || $slice_credential == '') {
    error_log("am_client cannot act on a slice without a credential");
    return("Missing slice credential");
  }
  error_log("CS slice_credential = ".print_r(debug_backtrace(), True));
  
  $member_id = $user->account_id;
  $msg = "User $member_id calling CreateSliver at $am_url on $slice_urn";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  $rspec = file_get_contents($rspec_filename);
  log_action("CreateSliver", $user, $am_url, $slice_urn, $rspec);
  $slice_credential_filename = writeDataToTempFile($slice_credential, $user->username . "-cred-");
  $args = array("--slicecredfile", 
		$slice_credential_filename, 
		'createsliver',
		$slice_urn,
		$rspec_filename);
  // FIXME: Note that this AM has resources
  // slice_id, am_url or ID, duration?
  $output = invoke_omni_function($am_url, $user, $args, $slice_users);
  unlink($slice_credential_filename);
  return $output;
}

// Get sliver status at an AM
function sliver_status($am_url, $user, $slice_credential, $slice_urn)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  if (! isset($slice_credential) || is_null($slice_credential) || $slice_credential == '') {
    error_log("am_client cannot act on a slice without a credential");
    return("Missing slice credential");
  }

  // Skip the log message, it's too detailed
  // $member_id = $user->account_id;
  // $msg = "User $member_id calling SliverStatus at $am_url on $slice_urn";
  // geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  // log_action("SliverStatus", $user, $am_url, $slice_urn);
  $slice_credential_filename = writeDataToTempFile($slice_credential, $user->username . "-cred-");
  $args = array("--slicecredfile",
		$slice_credential_filename,
		'sliverstatus',
		$slice_urn);
  $output = invoke_omni_function($am_url, $user, $args);
  unlink($slice_credential_filename);
  return $output;
}

// Delete a sliver at an AM
function delete_sliver($am_url, $user, $slice_credential, $slice_urn)
{
  if (! isset($am_url) || is_null($am_url) ){
    if (!(is_array($am_url) || $am_url != '')) {
      error_log("am_client cannot invoke Omni without an AM URL");
      return("Missing AM URL");
    }
  }

  if (! isset($slice_credential) || is_null($slice_credential) || $slice_credential == '') {
    error_log("am_client cannot act on a slice without a credential");
    return("Missing slice credential");
  }

  $member_id = $user->account_id;
  $msg = "User $member_id calling DeleteSliver at $am_url on $slice_urn";
  geni_syslog(GENI_SYSLOG_PREFIX::PORTAL, $msg);
  log_action("DeleteSliver", $user, $am_url, $slice_urn);
  $slice_credential_filename = writeDataToTempFile($slice_credential, $user->username . "-cred-");
  $args = array("--slicecredfile",
		$slice_credential_filename,
		'deletesliver',
		$slice_urn);
  // Note that this AM no longer has resources
  $output = invoke_omni_function($am_url, $user, $args);
  unlink($slice_credential_filename);
  return $output;
}

function ready_to_login($am_url, $user, $slice_cred, $slice_urn)
{
  global $portal_gcf_dir;

  $tmp_files = write_omni_config($user);
  $omni_config = $tmp_files[0];

  $slice_cred_file = writeDataToTempFile($slice_cred, $user->username . "-cred-");
  $tmp_files[] = $slice_cred_file;

  $cmd_array = array($portal_gcf_dir . '/examples/readyToLogin.py',
                     '-c', $omni_config,
                     '-a', $am_url,
                     '--slicecredfile', $slice_cred_file,
                     $slice_urn);
  $command = implode(" ", $cmd_array);

  error_log("COMMAND = " . $command);
  putenv("PYTHONPATH=$portal_gcf_dir/src");
  $handle = popen($command . " 2>&1", "r");
  $output= '';
  $read = fread($handle, 1024);
  while($read != null) {
    if ($read != null)
      $output = $output . $read;
    $read = fread($handle, 1024);
  }
  pclose($handle);

  /* Now delete all the tmp files. */
  foreach ($tmp_files as $f) {
    unlink($f);
  }

  return $output;
}

?>
