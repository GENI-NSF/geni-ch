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

require_once('response_format.php');
require_once('util.php');
require_once('guard.php');
require_once 'geni_syslog.php';

//
// requires php5-xmlrpc (as a .deb).
//

// CH API XML/RPC client abstraction.
// If $signer (also called user) is supplied, will use private key and cert to sign 
// messages.
class XMLRPCClient
{
  private $url;
  private $signer;
  private $combined = null;   // memory cache of PEM encoded cert+privatekey
  private $keyfile = null;    // name of the keyfile written to (if known)

  // this is intended to allow for the maintenance of a cache of 
  // constructed instances, but requires a long-lived php process (along
  // with access to an appropriately long-lived cache variable) to 
  // get substantial benefits.  The _SESSION array is not a good match
  // for such a cache, since it gets serialized to disk between invocations
  // and objects are destructed after serializing, leaving things like
  // the signer files broken on the disk.
  public static function get_client($url, $signer=null) {
    return $client = new XMLRPCClient($url, $signer);
  }    

  // arguments:
  //  
  function __construct($url, $signer=null)
  {
    $this->url = $url;
    $this->signer = $signer;
    if (!is_null($signer)) {
      $this->private_key = $signer->privateKey();
      $this->certificate = $signer->certificate();
    }
  }

  // clean up by deleting the cred file if we made one
  function __destruct() 
  {
    if (! is_null($this->keyfile)) {
      unlink($this->keyfile);
      $this->keyfile = null;  // wipe out the variable just to be sure
    }
  }
  // magic calls.  $this->foo(arg1, arg2) turns into:
  //     $this->__call("foo", array(arg1, arg2))
  public function __call($fun, $args)
  {
    return $this->call($fun, $args);
  }

  // if the function called has a leading '_' the return value will not be processed
  // using the usual triple.
  public function call($fun, $args)
  {
    $rawreturn = false;
    if (strpos($fun, '_')==0) {
      $rawreturn = true;
      $fun = substr($fun, 1);
    }

    $request = xmlrpc_encode_request($fun, $args);

    // mik: I would have liked to use the following, but it
    // had problems dealing with HTTPS+POST in some situations
    // Note: It *might* have been that it wanted the content-length header
    // added, but CURL works, so we'll go with it.
    //$context = stream_context_create(array('http' => $opts));
    //$file = file_get_contents($this->url, false, $context);
    $ch = curl_init();
    $headers = array("Content-Type: text/xml",
		     "Content-Length: ".strlen($request),
		     "\r\n");
    curl_setopt($ch, CURLOPT_URL, $this->url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // enable this
    // CURLOPT_CAPATH, /path/to/CA/dir
    //

    $pemf = null;
    if (!is_null($this->signer)) {
      if (is_null($this->keyfile)) {
	//	error_log("SIGNER = " . print_r($this->signer, true));
	$pemf = $this->_write_combined_credentials();
	$this->keyfile = $pemf;
      }
      curl_setopt($ch, CURLOPT_SSLKEY, $this->keyfile);
      curl_setopt($ch, CURLOPT_SSLKEYTYPE, "PEM");
      curl_setopt($ch, CURLOPT_SSLCERT, $this->keyfile);
    }

    //   error_log("CURL : " . $this->url);
    $ret = curl_exec($ch);
    if ($ret === FALSE) {
      error_log("CHAPI: CURL_ERROR = " . curl_error($ch));
    }

    curl_close($ch);  // TODO: would be nice to reuse these connections at this level
    
    // keyfile cleanup is handled by the destructor

    if ($rawreturn) {
      return $result;
    }

    $result = xmlrpc_decode($ret);

    return $this->result_handler($result);
  }

  // Write the combined cert (cert and private key) to a file for our transport.
  // the signer instance has files, but they are raw binary, rather than the
  // PEM encoded files that cURL expects.
  //
  // TODO: figure out how to use the raw files rather than having to write these.
  //
  // arguments:
  //   $file: if null, will create a temporary file, returning the name.  Otherwise, 
  //     will write to the filename specified. 
  // return:
  //   the name of the file written to.
  function _write_combined_credentials($file=null) {
    if (is_null($this->combined)) {
      openssl_pkey_export($this->private_key, $pkx);
      openssl_x509_export($this->certificate, $cx);
      $this->combined = $pkx . $cx;
    }
    if (is_null($file)) {
      $file = tempnam(sys_get_temp_dir(), "signer");
    }
    file_put_contents($file, $this->combined);
    return $file;
  }


  // unpack the CHAPI results, retaining compatibilty with the 
  // old put_message functionality:  If $put_message_result_handler
  // is defined (and not null), invoke it to process the results
  // otherwise do the default thing.
  //
  function result_handler($result)
  {
    // support the old functionality
    global $put_message_result_handler;
    if (isset($put_message_result_handler)) {
      if ($put_message_result_handler != null) {
	return $put_message_result_handler($result);
      }
    }
   
    // default handling
    if (isset($result['faultString'])) {
      error_log("SCRIPT_NAME = " . $_SERVER['SCRIPT_NAME']);
      error_log("ERROR.OUTPUT " . print_r($result['faultString'], true));
      relative_redirect('error-text.php' . "?error=" . urlencode($result['faultString']));
    }

    if ($result[RESPONSE_ARGUMENT::CODE] != RESPONSE_ERROR::NONE) {
      error_log("SCRIPT_NAME = " . $_SERVER['SCRIPT_NAME']);
      error_log("ERROR.CODE " . print_r($result[RESPONSE_ARGUMENT::CODE], true));
      error_log("ERROR.VALUE " . print_r($result[RESPONSE_ARGUMENT::VALUE], true));
      error_log("ERROR.OUTPUT " . print_r($result[RESPONSE_ARGUMENT::OUTPUT], true));
      
      relative_redirect('error-text.php' . "?error=" . urlencode($result[RESPONSE_ARGUMENT::OUTPUT]));
    }
    return $result[RESPONSE_ARGUMENT::VALUE];
  }

  // get the "credentials" blob needed for various CHAPI service calls,
  // mainly in support of SPEAKS-FOR functionality.
  // Some future use will likely want to use $this->signer
  // Note: this is creds() rather than get_credentials() because there is an sa->get_credentials()
  function creds() {
    return array();
  }
}


// Session cache access.  This is a simpler static interface than 
// session_cache.php
// 
function get_session_cached($skey)
{
  if(!isset($_SESSION)) {
    session_start(); // make sure that _session exists
  }
  if (!array_key_exists($skey, $_SESSION)) {
    $_SESSION[$skey] = array();
  }
  return $_SESSION[$skey];
}

function set_session_cached($skey, $ar)
{
  if(!isset($_SESSION)) {
    session_start(); // make sure that _session exists
  }
  $_SESSION[$skey] = $ar;
  return $ar;
}

function get_session_cached_value($skey, $valuekey)
{
  $cache = get_session_cached($skey);
  if (array_key_exists($valuekey, $cache)) {
    return $cache[$valuekey];
  } else {
    return null;
  }
}

function set_session_cached_value($skey, $valuekey, $value)
{
  $cache = get_session_cached($skey);
  $cache[$valuekey] = $value;
  set_session_cached($skey, $cache);
}
