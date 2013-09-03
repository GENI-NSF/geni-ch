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
  private $rawreturn = FALSE;

  public function __construct($url, $signer=null, $rawreturn=FALSE)
  {
    $this->url = $url;
    $this->signer = $signer;
    $this->rawreturn = $rawreturn;
  }
  public function __call($fun, $args)
  {
    return $this->call($fun, $args);
  }

  public function call($fun, $args)
  {
    $request = xmlrpc_encode_request($fun, $args);
    $ch = curl_init();
    $headers = array("Content-Type: text/xml",
		     "Content-Length: ".strlen($request),
		     "\r\n");
    curl_setopt($ch, CURLOPT_URL, $this->url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $query);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // enable this
    // CURLOPT_CAPATH, /path/to/CA/dir
    //

    $pemf = null;
    if ($this->signer) {
      $cert = $this->signer->certificate();
      //$key = $this->signer->privateKey();
      if ($cert) {
	$pemf = $this->signer->write();
	curl_setopt($ch, CURLOPT_SSLKEY, $pemf);
	curl_setopt($ch, CURLOPT_SSLKEYTYPE, "PEM");
	curl_setopt($ch, CURLOPT_SSLCERT, $pemf);
      }
    }
    $ret = curl_exec($ch);
    if ($ret === FALSE) {
      error_log("CHAPI: CURL_ERROR = " . curl_error($ch));
    }

    if (! is_null($pemf)) {
      unlink($pemf);
    }

    if ($this->rawreturn) {
      return $result;
    }

    $result = xmlrpc_decode($ret);

    // TODO: restore compatibility with old put_message_handler API
    return $this->default_put_message_result_handler($result);
  }

  public function call_old($fun, $args)
  {
    $request = xmlrpc_encode_request($fun, $args);
    //print_r($request);
    //    'verify_peer' => TRUE, // enable verificatin of SSL cert
    //    'allow_self_signed' => TRUE, // accept self-signed certs, reqires verify_peer
    //    'cafile' => "/path/to/CA/file.pem",
    //    'capath' => "/path/to/CA/directory",
    //    'local_cert' => "/path/to/cert.pem",
    //    'passphrase' => "passphrasetounlocklocal_cert",
    // maybe also consider capture_peer_cert, SNI_enabled, etc: see http://www.php.net/manual/en/context.ssl.php
    $opts = array('method' => "POST",
		  'header' => "Content-Type: text/xml",
		  'content' => $request,
		  'verify_peer' => TRUE);
    $pemf = null;
    if ($this->signer) {
      //$cert = $this->signer->certificate();
      //$key = $this->signer->privateKey();
      $pemf = $this->signer->write();
      if ($cert) {
	$opts['local_cert']=$pemf;
      }
    }
    $context = stream_context_create(array('http' => $opts));
    $file = file_get_contents($this->url, false, $context);
    $result = xmlrpc_decode($file);

    if (! is_null($pemf)) {
      unlink($pemf);
    }

    if ($this->rawreturn) {
      return $result;
    }

    // compatibility with old put_message_handler API

    // If a custom handler is set, use it.
    global $put_message_result_handler;
    //  error_log("PUT_MESSAGE:PUT_MESSAGE_RESULT_HANDLER = " . $put_message_result_handler);
    //    if($put_message_result_handler != null) {
    //      return $put_message_result_handler($result);
    //    } else {
    // Otherwise, here's the default handler
    return $this->default_put_message_result_handler($result);
    //    }
  }

  function default_put_message_result_handler($result)
  {
    //  error_log("Decoded raw result : " . $result);
    
    //  error_log("MH.RESULT = " . print_r($result, true));
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

    //     error_log("ERROR.OUTPUT " . print_r($result[RESPONSE_ARGUMENT::OUTPUT], true));
    
    return $result[RESPONSE_ARGUMENT::VALUE];
  }

}

// $client = new XMLRPCClient('https://marilac.gpolab.bbn.com:8001/MA');
// $response = $client->get_version();

//if ($response && xmlrpc_is_fault($response)) {
//  trigger_error("xmlrpc: $response[faultString] ($response[faultCode])");
//} else {
//  print_r($response);
//}