<?php
//----------------------------------------------------------------------
// Copyright (c) 2013 Raytheon BBN Technologies
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

require_once('chapi.php');

// Service to support caching variables obtained by system services within the given session
// Maintain values keyed by 'key' in the $_SESSION variable dictionary

// Lookup value based on key
// If the value is in the cache and isn't stale, return it
// Otherwise, refresh value by invoking methods on given URL
// $refresh_arguments is a dictionary of arguments ot the call, optionally null (= no arguments)
function session_cache_lookup($key, $refresh_timeout, $refresh_url, $refresh_method, $refresh_arguments)
{
  if(!isset($_SESSION)) {
    //    error_log("Starting Session");
    session_start();
    //    if (isset($_SESSION)) { error_log("SET"); } else { error_log("NOT SET"); }
    //  } else {
    //    error_log("session_cache.lookup: IS SET " . print_r($_SESSION[$key], true));
  }

  $timeout_key = $key . "_TIMEOUT";

  // We need to refresh the cache if:
  // 1- There's no entry in the cache
  // 2- There's no time of last update
  // 3- The time of last update is null
  // 4- The time of last update is longer than $refresh_timeout ago
  $now = time();

  if(!array_key_exists($key, $_SESSION) || 
     !array_key_exists($timeout_key, $_SESSION) || 
     ($_SESSION[$timeout_key] == null) || 
     ($now - $_SESSION[$timeout_key] > $refresh_timeout)) 
    {
      $refresh_message['operation'] = $refresh_method;
      if ($refresh_arguments != null) {
	foreach($refresh_arguments as $arg_key => $arg_val) {
	  $refresh_message[$arg_key] = $arg_val;
	}
      }
      $client = XMLRPCClient::get_client($refresh_url);
      $response = $client->$refresh_method();  // ignores args

      $_SESSION[$key] = $response;
      $_SESSION[$timeout_key] = $now;
      //      error_log("Refreshing cache for key $key : message = " . print_r($refresh_message, true) . " " . $key . " " . $_SESSION[$key] . " " . $timeout_key . " " . $_SESSION[$timeout_key] . " " . $now . " " . $refresh_timeout);
  }

  $value = $_SESSION[$key];
  return $value;

}

// Force a refresh on the given key on next lookup, no mater the timeout
function session_cache_flush($key)
{
  // If we haven't set up the session, don't bother: there's nothing to flush
  if(!isset($_SESSION)) {
    return;
  }

  // If the session has no info about this key, don't bother: there's nothing to flush
  if(!array_key_exists($key, $_SESSION)) {
    return;
  }

  $timeout_key = $key . "_TIMEOUT";
  if(!array_key_exists($timeout_key, $_SESSION)) {
    error_log("Error: key $key exists but not key $timeout_key");
    return;
  }

  $_SESSION[$timeout_key] = null;  // MIK: shouldn't this be unset($_SESSION[$timeout_key])?

}

?>
