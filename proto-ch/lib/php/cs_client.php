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

require_once('permission_manager.php');
require_once('chapi.php');

// Client side interface of GENI Clearinghouse Credential Store (CS)


// A cache of a principal's permissions indexed by ID
if(!isset($permission_cache)) {
  //  error_log("SETTING PERMISSION_CACHE");
  $permission_cache = array();

}

function get_attributes($cs_url, $signer, $principal, $context_type, $context)
{
  $client = XMLRPCClient::get_client($cs_url, $signer);
  $options = array('_dummy' => null); // Force this to be a dictionary, not an array on other side
  return $client->get_attributes($principal, $context_type, $context, 
				 $client->creds(), $options);

}

function get_permissions($cs_url, $signer, $principal)
{
  global $permission_cache;

  if (array_key_exists($principal, $permission_cache)) {
    //    error_log("CACHE HIT get_permissions : " . $principal);
    return $permission_cache[$principal];
  }

  $client = XMLRPCClient::get_client($cs_url, $signer);
  $options = array('_dummy' => 'null'); // Force this to be a dictionary, not an array on other side
  $result =  $client->get_permissions($principal, $client->creds(), 
				      $options);
  //  error_log("RESULT = " . print_r($result, true));
  
  $pm = compute_permission_manager($result);
  $permission_cache[$principal] = $pm;
  return $pm;
}

?>