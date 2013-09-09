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

// Helper functions for the CHAPI-based client methods

// Convert the keys of a given data object row from 'chapi' names to 'portal' names
function convert_row($row, $mapping)
{
  $nrow = array();
  foreach ($row as $k=>$v) {
    if (array_key_exists($k, $mapping)) 
      $nrow[$mapping[$k]] = $v;
  }
  return $nrow;
}

$CHAPI_ROLE_TO_CS_ROLE = array("LEAD" => 1, "ADMIN" => 2, "MEMBER" => 3, "AUDITOR" => 4, "OPERATOR" => 5);

function convert_role($row)
{
  global $CHAPI_ROLE_TO_CS_ROLE;
  if (array_key_exists('role', $row)) {
    $role = $row['role'];
    $new_role = $CHAPI_ROLE_TO_CS_ROLE[$role];
    $row['role'] = $new_role;
  }
  return $row;
}



?>
