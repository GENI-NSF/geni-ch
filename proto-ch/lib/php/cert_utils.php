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

require_once('file_utils.php');

/**
 * Functions to help with certificate handling.
 */


function make_csr($uuid, &$csrfile, &$keyfile, $temp_prefix="geni-")
{
  $csrfile = null;
  $keyfile = null;
  $keytmpfile = tempnam(sys_get_temp_dir(), $temp_prefix);
  $csrtmpfile = tempnam(sys_get_temp_dir(), $temp_prefix);
  $cmd_array = array('/usr/bin/openssl',
                     'req',
                     '-new',
                     '-newkey', 'rsa:1024',
                     '-nodes',
                     '-keyout', $keytmpfile,
                     '-out', $csrtmpfile,
                     '-batch',
                     '2>&1');
  $command = implode(" ", $cmd_array);
  $result = exec($command, $output, $status);
  if ($status == 0) {
    $csrfile = $csrtmpfile;
    $keyfile = $keytmpfile;
    return TRUE;
  } else {
    error_log("Command $command returned status $status.\n");
    error_log("Output was: " . print_r($output));
    return FALSE;
  }
}

function sign_csr($csr_file, $uuid, $email, $urn, $signer_cert_file, $signer_key_file,
                  &$cert, $temp_prefix="geni-")
{
  $cert_file = tempnam(sys_get_temp_dir(), $temp_prefix);

  // Write the extension data to a file
  $extname = 'v3_user';
  $extdata = "[ $extname ]\n"
    . "subjectKeyIdentifier=hash\n"
    . "authorityKeyIdentifier=keyid:always,issuer:always\n"
    . "basicConstraints = CA:false\n";
  if ($email) {
    $extdata .= "subjectAltName=email:copy,URI:$urn,URI:urn:uuid:$uuid\n";
    $subject = "/CN=$uuid/emailAddress=$email";
  } else {
    $extdata .= "subjectAltName=URI:$urn,URI:urn:uuid:$uuid\n";
    $subject = "/CN=$uuid";
  }
  $ext_file = writeDataToTempFile($extdata, $temp_prefix);
  $cmd_array = array('/usr/bin/openssl',
                     'ca',
                     // FIXME: this should be an MA-specific openssl conf file.
                     '-config', '/usr/share/geni-ch/CA/openssl.cnf',
                     '-extfile', $ext_file,
                     '-policy', 'policy_anything',
                     '-out', $cert_file,
                     '-in', $csr_file,
                     '-extensions', $extname,
                     '-batch',
                     '-notext',
                     '-cert', $signer_cert_file,
                     '-keyfile', $signer_key_file,
                     '-subj', $subject,
                     '2>&1');
  $command = implode(" ", $cmd_array);
  $result = exec($command, $output, $status);
  if ($status != 0) {
    error_log("Command $command returned status $status.\n");
    error_log("Output was: " . print_r($output));
    return FALSE;
  }

  /*
   * Now load the contents of the generated cert and concatentate with
   * the signer to form a chain certificate (suitable for framing).
   */
  $cert_pem = file_get_contents($cert_file);
  if (! $cert_pem) {
    error_log("Unable to load user cert from $cert_file.\n");
    return FALSE;
  }
  $signer_pem = file_get_contents($signer_cert_file);
  if (! $signer_pem) {
    error_log("Unable to load signer cert from $signer_cert_file.\n");
    return FALSE;
  }
  $cert = $cert_pem . $signer_pem;

  unlink($cert_file);
  unlink($ext_file);
  return TRUE;
}

function make_cert_and_key($uuid, $email, $urn,
                           $signer_cert_file, $signer_key_file,
                           &$cert, &$key, $temp_prefix="geni-")
{
  $cert = null;
  $key = null;

  if (! make_csr($uuid, $csr_file, $key_file, $temp_prefix)) {
    return FALSE;
  }

  if (! sign_csr($csr_file, $uuid, $email, $urn, $signer_cert_file, $signer_key_file,
                 $cert, $temp_prefix)) {
    return FALSE;
  }

  $key = file_get_contents($key_file);
  unlink($csr_file);
  unlink($key_file);
  return TRUE;
}

function urn_from_cert($cert)
{
  $cert = openssl_x509_parse($cert);
  $extensions = $cert['extensions'];
  $subject_alt_name = $extensions['subjectAltName'];
  $fields = array_map('trim', explode(",", $subject_alt_name));
  $pattern = '/^\s*URI:urn:publicid:IDN/';
  $matches = preg_grep($pattern, $fields);
  $matches = array_values($matches);
  if (count($matches) > 0) {
    $result = substr($matches[0], 4);
  } else {
    $result = "NO+URN+FOUND";
  }
  return $result;
}

function parse_urn($urn, &$authority, &$type, &$name)
{
  $pattern = '/urn:publicid:IDN\+([^\+]+)\+([^\+]+)\+([^\+]+)$/';
  $match_count = preg_match($pattern, $urn, $matches);
  if ($match_count == 1) {
    $authority = $matches[1];
    $type = $matches[2];
    $name = $matches[3];
    return TRUE;
  } else {
    $authority = null;
    $type = null;
    $name = null;
    return FALSE;
  }
}

function make_urn($authority, $type, $name)
{
  return "urn:publicid:IDN+$authority+$type+$name";
}

?>