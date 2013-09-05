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
  private $rawreturn = FALSE;
  private $combined = null;

  // arguments:
  //  
  public function __construct($url, $signer=null, $rawreturn=FALSE)
  {
    $this->url = $url;
    $this->signer = $signer;
    if (!is_null($signer)) {
      $this->private_key = $signer->privateKey();
      $this->certificate = $signer->certificate();
    }
    $this->rawreturn = $rawreturn;
  }

  // magic calls.  $this->foo(arg1, arg2) turns into $this->__call("foo", array(arg1, arg2))
  public function __call($fun, $args)
  {
    return $this->call($fun, $args);
  }

  public function call($fun, $args)
  {
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
      //error_log("SIGNER = " . print_r($this->signer, true));
      $pemf = $this->_write_combined_credentials();
      curl_setopt($ch, CURLOPT_SSLKEY, $pemf);
      curl_setopt($ch, CURLOPT_SSLKEYTYPE, "PEM");
      curl_setopt($ch, CURLOPT_SSLCERT, $pemf);
    }
    $ret = curl_exec($ch);
    if ($ret === FALSE) {
      error_log("CHAPI: CURL_ERROR = " . curl_error($ch));
    }

    curl_close($ch);

    if (! is_null($pemf)) {
      unlink($pemf);
    }

    if ($this->rawreturn) {
      return $result;
    }

    $result = xmlrpc_decode($ret);

    return $this->result_handler($result);
  }

  // Write the combined cert to a file.
  // arguments:
  //   $file: if null, will create a temporary file, returning the name.  Otherwise, writes to the file
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
  function get_credentials() {
    return array();
  }
}
