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

require_once('chapi.php');
require_once('cs_constants.php');

// Client side services for Logging of events within GENI clearinghouse

// Log an event to the logging service
// Event consists of 
//    message - Text of log message
//    attributes - Dictionaary of name/value pairs by which to tag and retrieve mmessage
//    user_id (the writer of the log entry)
function log_event($log_url, $signer, $message, $attributes, $user_id )
{
  $client = XMLRPCClient::get_client($log_url, $signer);
  $client->log_event($message, $attributes, $user_id);
}

function get_log_entries_by_author($log_url, $signer, $user_id, $num_hours=24)
{
  $client = XMLRPCClient::get_client($log_url, $signer);
  $entries = $client->get_log_entries_by_author($user_id, $num_hours);
  return $entries;
}

// Helper function to turn context/context_id into attribute dictionary
function get_attribute_for_context($context_type, $context_id)
{
  global $CS_CONTEXT_TYPE_NAME;
  $context_type_as_name = $CS_CONTEXT_TYPE_NAME[$context_type];
  $attribute[$context_type_as_name] = $context_id;
  return $attribute;
}

function get_log_entries_for_context($log_url, $signer, $context_type, $context_id, $num_hours=24)
{
  $client = XMLRPCClient::get_client($log_url, $signer);
  $entries = $client->get_log_entries_for_context($context_type, $context_id, $num_hours);
  return $entries;
}

function get_attributes_for_log_entry($log_url, $signer, $event_id)
{
  $client = XMLRPCClient::get_client($log_url, $signer);
  $attribs = $client->get_attributes_for_log_entry($event_id);
  return $attribs;
}

// This is a helper function to allow sorting lists of 
// log entries by event_time - new entries first
function compare_log_entries($ent1, $ent2)
{
  $t1 = $ent1[LOGGING_TABLE_FIELDNAME::EVENT_TIME];
  $t2 = $ent2[LOGGING_TABLE_FIELDNAME::EVENT_TIME];
  if ($t1 == $t2)
    return 0;
  else if ($t1 < $t2)
    return 1;
  else
    return -1;
}




?>