<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - DCAuthWebServer Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_DCAuthWebServer {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_dcauthwebserver_open(SECUREBLACKBOX_OEMKEY_998);
    secureblackbox_dcauthwebserver_register_callback($this->handle, 1, array($this, 'fireAccept'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 2, array($this, 'fireAuthAttempt'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 3, array($this, 'fireBeforeOpenStorage'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 4, array($this, 'fireCertificateValidate'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 5, array($this, 'fireConnect'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 6, array($this, 'fireCustomParametersReceived'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 7, array($this, 'fireDisconnect'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 8, array($this, 'fireError'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 9, array($this, 'fireExternalSign'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 10, array($this, 'fireKeySecretNeeded'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 11, array($this, 'fireLog'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 12, array($this, 'fireNotification'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 13, array($this, 'fireParameterReceived'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 14, array($this, 'firePasswordNeeded'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 15, array($this, 'fireReadOption'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 16, array($this, 'fireSelectCert'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 17, array($this, 'fireSignRequest'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 18, array($this, 'fireSignRequestCompleted'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 19, array($this, 'fireTLSEstablished'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 20, array($this, 'fireTLSPSK'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 21, array($this, 'fireTLSShutdown'));
    secureblackbox_dcauthwebserver_register_callback($this->handle, 22, array($this, 'fireWriteOption'));
  }
  
  public function __destruct() {
    secureblackbox_dcauthwebserver_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_dcauthwebserver_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_dcauthwebserver_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_dcauthwebserver_do_config($this->handle, $configurationstring);
		$err = secureblackbox_dcauthwebserver_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Terminates a client connection.
  *
  * @access   public
  * @param    int64    connectionid
  * @param    boolean    forced
  */
  public function doDropClient($connectionid, $forced) {
    $ret = secureblackbox_dcauthwebserver_do_dropclient($this->handle, $connectionid, $forced);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enumerates the connected clients.
  *
  * @access   public
  */
  public function doListClients() {
    $ret = secureblackbox_dcauthwebserver_do_listclients($this->handle);
		$err = secureblackbox_dcauthwebserver_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Takes a snapshot of the connection's properties.
  *
  * @access   public
  * @param    int64    connectionid
  */
  public function doPinClient($connectionid) {
    $ret = secureblackbox_dcauthwebserver_do_pinclient($this->handle, $connectionid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Starts the server.
  *
  * @access   public
  */
  public function doStart() {
    $ret = secureblackbox_dcauthwebserver_do_start($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Stops the server.
  *
  * @access   public
  */
  public function doStop() {
    $ret = secureblackbox_dcauthwebserver_do_stop($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_dcauthwebserver_get($this->handle, 0);
  }
 /**
  * Indicates whether the server is active and is listening to new connections.
  *
  * @access   public
  */
  public function getActive() {
    return secureblackbox_dcauthwebserver_get($this->handle, 1 );
  }


 /**
  * Specifies the content of AllowOrigin header of the service reply.
  *
  * @access   public
  */
  public function getAllowOrigin() {
    return secureblackbox_dcauthwebserver_get($this->handle, 2 );
  }
 /**
  * Specifies the content of AllowOrigin header of the service reply.
  *
  * @access   public
  * @param    string   value
  */
  public function setAllowOrigin($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables basic authentication.
  *
  * @access   public
  */
  public function getAuthBasic() {
    return secureblackbox_dcauthwebserver_get($this->handle, 3 );
  }
 /**
  * Enables or disables basic authentication.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthBasic($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables digest authentication.
  *
  * @access   public
  */
  public function getAuthDigest() {
    return secureblackbox_dcauthwebserver_get($this->handle, 4 );
  }
 /**
  * Enables or disables digest authentication.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthDigest($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies digest expiration time for digest authentication.
  *
  * @access   public
  */
  public function getAuthDigestExpire() {
    return secureblackbox_dcauthwebserver_get($this->handle, 5 );
  }
 /**
  * Specifies digest expiration time for digest authentication.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthDigestExpire($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies authentication realm for digest and NTLM authentication.
  *
  * @access   public
  */
  public function getAuthRealm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 6 );
  }
 /**
  * Specifies authentication realm for digest and NTLM authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthRealm($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the bound listening port.
  *
  * @access   public
  */
  public function getBoundPort() {
    return secureblackbox_dcauthwebserver_get($this->handle, 7 );
  }


 /**
  * Specifies the signing certificate password.
  *
  * @access   public
  */
  public function getCertPassword() {
    return secureblackbox_dcauthwebserver_get($this->handle, 8 );
  }
 /**
  * Specifies the signing certificate password.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertPassword($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the endpoint where the error originates from.
  *
  * @access   public
  */
  public function getErrorOrigin() {
    return secureblackbox_dcauthwebserver_get($this->handle, 9 );
  }
 /**
  * Indicates the endpoint where the error originates from.
  *
  * @access   public
  * @param    int   value
  */
  public function setErrorOrigin($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The severity of the error that happened.
  *
  * @access   public
  */
  public function getErrorSeverity() {
    return secureblackbox_dcauthwebserver_get($this->handle, 10 );
  }
 /**
  * The severity of the error that happened.
  *
  * @access   public
  * @param    int   value
  */
  public function setErrorSeverity($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_dcauthwebserver_get($this->handle, 11 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_dcauthwebserver_get($this->handle, 12 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_dcauthwebserver_get($this->handle, 13 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 14 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_dcauthwebserver_get($this->handle, 15 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_dcauthwebserver_get($this->handle, 16 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_dcauthwebserver_get($this->handle, 17 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_dcauthwebserver_get($this->handle, 18 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 19 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the handshake timeout in milliseconds.
  *
  * @access   public
  */
  public function getHandshakeTimeout() {
    return secureblackbox_dcauthwebserver_get($this->handle, 20 );
  }
 /**
  * Specifies the handshake timeout in milliseconds.
  *
  * @access   public
  * @param    int   value
  */
  public function setHandshakeTimeout($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The host to bind the listening port to.
  *
  * @access   public
  */
  public function getHost() {
    return secureblackbox_dcauthwebserver_get($this->handle, 21 );
  }
 /**
  * The host to bind the listening port to.
  *
  * @access   public
  * @param    string   value
  */
  public function setHost($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the KeyID of the pre-shared authentication key.
  *
  * @access   public
  */
  public function getKeyId() {
    return secureblackbox_dcauthwebserver_get($this->handle, 22 );
  }
 /**
  * Specifies the KeyID of the pre-shared authentication key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyId($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared authentication key.
  *
  * @access   public
  */
  public function getKeySecret() {
    return secureblackbox_dcauthwebserver_get($this->handle, 23 );
  }
 /**
  * The pre-shared authentication key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySecret($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The client's IP address.
  *
  * @access   public
  */
  public function getPinnedClientAddress() {
    return secureblackbox_dcauthwebserver_get($this->handle, 24 );
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getPinnedClientChainValidationDetails() {
    return secureblackbox_dcauthwebserver_get($this->handle, 25 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getPinnedClientChainValidationResult() {
    return secureblackbox_dcauthwebserver_get($this->handle, 26 );
  }


 /**
  * The cipher suite employed by this connection.
  *
  * @access   public
  */
  public function getPinnedClientCiphersuite() {
    return secureblackbox_dcauthwebserver_get($this->handle, 27 );
  }


 /**
  * Specifies whether client authentication was performed during this connection.
  *
  * @access   public
  */
  public function getPinnedClientClientAuthenticated() {
    return secureblackbox_dcauthwebserver_get($this->handle, 28 );
  }


 /**
  * The digest algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientDigestAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 29 );
  }


 /**
  * The symmetric encryption algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientEncryptionAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 30 );
  }


 /**
  * The client connection's unique identifier.
  *
  * @access   public
  */
  public function getPinnedClientID() {
    return secureblackbox_dcauthwebserver_get($this->handle, 31 );
  }


 /**
  * The key exchange algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientKeyExchangeAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 32 );
  }


 /**
  * The length of the key exchange key of a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientKeyExchangeKeyBits() {
    return secureblackbox_dcauthwebserver_get($this->handle, 33 );
  }


 /**
  * The elliptic curve used in this connection.
  *
  * @access   public
  */
  public function getPinnedClientNamedECCurve() {
    return secureblackbox_dcauthwebserver_get($this->handle, 34 );
  }


 /**
  * Indicates whether the chosen ciphersuite provides perfect forward secrecy (PFS).
  *
  * @access   public
  */
  public function getPinnedClientPFSCipher() {
    return secureblackbox_dcauthwebserver_get($this->handle, 35 );
  }


 /**
  * The remote port of the client connection.
  *
  * @access   public
  */
  public function getPinnedClientPort() {
    return secureblackbox_dcauthwebserver_get($this->handle, 36 );
  }


 /**
  * The length of the public key.
  *
  * @access   public
  */
  public function getPinnedClientPublicKeyBits() {
    return secureblackbox_dcauthwebserver_get($this->handle, 37 );
  }


 /**
  * Indicates whether a TLS-enabled connection was spawned from another TLS connection.
  *
  * @access   public
  */
  public function getPinnedClientResumedSession() {
    return secureblackbox_dcauthwebserver_get($this->handle, 38 );
  }


 /**
  * Indicates whether TLS or SSL is enabled for this connection.
  *
  * @access   public
  */
  public function getPinnedClientSecureConnection() {
    return secureblackbox_dcauthwebserver_get($this->handle, 39 );
  }


 /**
  * The signature algorithm used in a TLS handshake.
  *
  * @access   public
  */
  public function getPinnedClientSignatureAlgorithm() {
    return secureblackbox_dcauthwebserver_get($this->handle, 40 );
  }


 /**
  * The block size of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getPinnedClientSymmetricBlockSize() {
    return secureblackbox_dcauthwebserver_get($this->handle, 41 );
  }


 /**
  * The key length of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getPinnedClientSymmetricKeyBits() {
    return secureblackbox_dcauthwebserver_get($this->handle, 42 );
  }


 /**
  * The total number of bytes received over this connection.
  *
  * @access   public
  */
  public function getPinnedClientTotalBytesReceived() {
    return secureblackbox_dcauthwebserver_get($this->handle, 43 );
  }


 /**
  * The total number of bytes sent over this connection.
  *
  * @access   public
  */
  public function getPinnedClientTotalBytesSent() {
    return secureblackbox_dcauthwebserver_get($this->handle, 44 );
  }


 /**
  * Contains the server certificate's chain validation log.
  *
  * @access   public
  */
  public function getPinnedClientValidationLog() {
    return secureblackbox_dcauthwebserver_get($this->handle, 45 );
  }


 /**
  * Indicates the version of SSL/TLS protocol negotiated during this connection.
  *
  * @access   public
  */
  public function getPinnedClientVersion() {
    return secureblackbox_dcauthwebserver_get($this->handle, 46 );
  }


 /**
  * The number of records in the PinnedClientCert arrays.
  *
  * @access   public
  */
  public function getPinnedClientCertCount() {
    return secureblackbox_dcauthwebserver_get($this->handle, 47 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getPinnedClientCertBytes($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 48 , $pinnedclientcertindex);
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getPinnedClientCertCAKeyID($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 49 , $pinnedclientcertindex);
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertFingerprint($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 50 , $pinnedclientcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getPinnedClientCertHandle($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 51 , $pinnedclientcertindex);
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getPinnedClientCertIssuer($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 52 , $pinnedclientcertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getPinnedClientCertIssuerRDN($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 53 , $pinnedclientcertindex);
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyAlgorithm($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 54 , $pinnedclientcertindex);
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyBits($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 55 , $pinnedclientcertindex);
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyFingerprint($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 56 , $pinnedclientcertindex);
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyUsage($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 57 , $pinnedclientcertindex);
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getPinnedClientCertPublicKeyBytes($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 58 , $pinnedclientcertindex);
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getPinnedClientCertSelfSigned($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 59 , $pinnedclientcertindex);
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getPinnedClientCertSerialNumber($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 60 , $pinnedclientcertindex);
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertSigAlgorithm($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 61 , $pinnedclientcertindex);
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getPinnedClientCertSubject($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 62 , $pinnedclientcertindex);
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getPinnedClientCertSubjectKeyID($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 63 , $pinnedclientcertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getPinnedClientCertSubjectRDN($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 64 , $pinnedclientcertindex);
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getPinnedClientCertValidFrom($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 65 , $pinnedclientcertindex);
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getPinnedClientCertValidTo($pinnedclientcertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 66 , $pinnedclientcertindex);
  }


 /**
  * Specifies the port number to listen for connections on.
  *
  * @access   public
  */
  public function getPort() {
    return secureblackbox_dcauthwebserver_get($this->handle, 67 );
  }
 /**
  * Specifies the port number to listen for connections on.
  *
  * @access   public
  * @param    int   value
  */
  public function setPort($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 67, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the lower limit of the listening port range for incoming connections.
  *
  * @access   public
  */
  public function getPortRangeFrom() {
    return secureblackbox_dcauthwebserver_get($this->handle, 68 );
  }
 /**
  * Specifies the lower limit of the listening port range for incoming connections.
  *
  * @access   public
  * @param    int   value
  */
  public function setPortRangeFrom($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 68, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the upper limit of the listening port range for incoming connections.
  *
  * @access   public
  */
  public function getPortRangeTo() {
    return secureblackbox_dcauthwebserver_get($this->handle, 69 );
  }
 /**
  * Specifies the upper limit of the listening port range for incoming connections.
  *
  * @access   public
  * @param    int   value
  */
  public function setPortRangeTo($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 69, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the ServerCert arrays.
  *
  * @access   public
  */
  public function getServerCertCount() {
    return secureblackbox_dcauthwebserver_get($this->handle, 70 );
  }
 /**
  * The number of records in the ServerCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setServerCertCount($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 70, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getServerCertBytes($servercertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 71 , $servercertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getServerCertHandle($servercertindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 72 , $servercertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setServerCertHandle($servercertindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 72, $value , $servercertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the default session timeout value in milliseconds.
  *
  * @access   public
  */
  public function getSessionTimeout() {
    return secureblackbox_dcauthwebserver_get($this->handle, 73 );
  }
 /**
  * Specifies the default session timeout value in milliseconds.
  *
  * @access   public
  * @param    int   value
  */
  public function setSessionTimeout($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signing service endpoint.
  *
  * @access   public
  */
  public function getSignEndpoint() {
    return secureblackbox_dcauthwebserver_get($this->handle, 74 );
  }
 /**
  * The signing service endpoint.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignEndpoint($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the signing certificate.
  *
  * @access   public
  */
  public function getSigningCertificate() {
    return secureblackbox_dcauthwebserver_get($this->handle, 75 );
  }
 /**
  * Specifies the signing certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setSigningCertificate($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_dcauthwebserver_get($this->handle, 76 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_dcauthwebserver_get($this->handle, 77 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_dcauthwebserver_get($this->handle, 78 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_dcauthwebserver_get($this->handle, 79 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_dcauthwebserver_get($this->handle, 80 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_dcauthwebserver_get($this->handle, 81 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 81, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the signing certificate residing in an alternative location.
  *
  * @access   public
  */
  public function getStorageId() {
    return secureblackbox_dcauthwebserver_get($this->handle, 82 );
  }
 /**
  * Specifies the signing certificate residing in an alternative location.
  *
  * @access   public
  * @param    string   value
  */
  public function setStorageId($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 82, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_dcauthwebserver_get($this->handle, 83 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 83, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_dcauthwebserver_get($this->handle, 84 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 84, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_dcauthwebserver_get($this->handle, 85 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 85, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_dcauthwebserver_get($this->handle, 86 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_dcauthwebserver_get($this->handle, 87 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 87, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_dcauthwebserver_get($this->handle, 88 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 88, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_dcauthwebserver_get($this->handle, 89 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 89, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_dcauthwebserver_get($this->handle, 90 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_dcauthwebserver_get($this->handle, 91 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 91, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_dcauthwebserver_get($this->handle, 92 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 92, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_dcauthwebserver_get($this->handle, 93 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 93, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_dcauthwebserver_get($this->handle, 94 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 94, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_dcauthwebserver_get($this->handle, 95 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 95, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_dcauthwebserver_get($this->handle, 96 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 96, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_dcauthwebserver_get($this->handle, 97 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 97, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the User arrays.
  *
  * @access   public
  */
  public function getUserCount() {
    return secureblackbox_dcauthwebserver_get($this->handle, 98 );
  }
 /**
  * The number of records in the User arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserCount($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 98, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  */
  public function getUserAssociatedData($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 99 , $userindex);
  }
 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserAssociatedData($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 99, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  */
  public function getUserBasePath($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 100 , $userindex);
  }
 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserBasePath($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 100, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's certificate.
  *
  * @access   public
  */
  public function getUserCert($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 101 , $userindex);
  }
 /**
  * Contains the user's certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserCert($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 101, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  */
  public function getUserData($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 102 , $userindex);
  }
 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserData($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 102, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getUserHandle($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 103 , $userindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setUserHandle($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 103, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  */
  public function getUserHashAlgorithm($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 104 , $userindex);
  }
 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserHashAlgorithm($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 104, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  */
  public function getUserIncomingSpeedLimit($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 105 , $userindex);
  }
 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserIncomingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 105, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  */
  public function getUserOutgoingSpeedLimit($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 106 , $userindex);
  }
 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOutgoingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 106, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user's authentication password.
  *
  * @access   public
  */
  public function getUserPassword($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 107 , $userindex);
  }
 /**
  * The user's authentication password.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserPassword($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 107, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  */
  public function getUserSharedSecret($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 108 , $userindex);
  }
 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserSharedSecret($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 108, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The registered name (login) of the user.
  *
  * @access   public
  */
  public function getUserUsername($userindex) {
    return secureblackbox_dcauthwebserver_get($this->handle, 109 , $userindex);
  }
 /**
  * The registered name (login) of the user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserUsername($userindex, $value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 109, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables the TLS requirement.
  *
  * @access   public
  */
  public function getUseTLS() {
    return secureblackbox_dcauthwebserver_get($this->handle, 110 );
  }
 /**
  * Enables or disables the TLS requirement.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseTLS($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 110, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the web site name to use in the certificate.
  *
  * @access   public
  */
  public function getWebsiteName() {
    return secureblackbox_dcauthwebserver_get($this->handle, 111 );
  }
 /**
  * Specifies the web site name to use in the certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setWebsiteName($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 111, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_dcauthwebserver_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_dcauthwebserver_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_dcauthwebserver_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Reports an incoming connection.
  *
  * @access   public
  * @param    array   Array of event parameters: remoteaddress, remoteport, accept    
  */
  public function fireAccept($param) {
    return $param;
  }

 /**
  * Fires when a connected client makes an authentication attempt.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, username, password, allow    
  */
  public function fireAuthAttempt($param) {
    return $param;
  }

 /**
  * Informs about imminent access to the certificate storage.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, storageid, signingcertificate, certificatepassword    
  */
  public function fireBeforeOpenStorage($param) {
    return $param;
  }

 /**
  * Fires when a client certificate needs to be validated.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, accept    
  */
  public function fireCertificateValidate($param) {
    return $param;
  }

 /**
  * Reports an accepted connection.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, remoteaddress, remoteport    
  */
  public function fireConnect($param) {
    return $param;
  }

 /**
  * Passes custom request parameters to the application.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, value    
  */
  public function fireCustomParametersReceived($param) {
    return $param;
  }

 /**
  * Fires to report a disconnected client.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid    
  */
  public function fireDisconnect($param) {
    return $param;
  }

 /**
  * Information about errors during data delivery.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, errorcode, description    
  */
  public function fireError($param) {
    return $param;
  }

 /**
  * Handles remote or external signing initiated by the server protocol.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, operationid, hashalgorithm, pars, data, signeddata    
  */
  public function fireExternalSign($param) {
    return $param;
  }

 /**
  * Requests the key secret from the application.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, keyid, keysecret    
  */
  public function fireKeySecretNeeded($param) {
    return $param;
  }

 /**
  * Reports a single log line.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, logtype, details    
  */
  public function fireLog($param) {
    return $param;
  }

 /**
  * This event notifies the application about an underlying control flow event.
  *
  * @access   public
  * @param    array   Array of event parameters: eventid, eventparam    
  */
  public function fireNotification($param) {
    return $param;
  }

 /**
  * Passes a standard request parameter to the user code.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, name, value    
  */
  public function fireParameterReceived($param) {
    return $param;
  }

 /**
  * Requests a password from the application.
  *
  * @access   public
  * @param    array   Array of event parameters: neededfor, id, password, cancel    
  */
  public function firePasswordNeeded($param) {
    return $param;
  }

 /**
  * Fires when the client sends in a read option request.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, name, value, success    
  */
  public function fireReadOption($param) {
    return $param;
  }

 /**
  * Requests certificate selection criteria from the application.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, commonname, keyid, keyusage, fingerprint, storetype    
  */
  public function fireSelectCert($param) {
    return $param;
  }

 /**
  * This event signifies the processing of an atomic signing request.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, hash, username, allow    
  */
  public function fireSignRequest($param) {
    return $param;
  }

 /**
  * This event signifies completion of the processing of an atomic signing request.
  *
  * @access   public
  * @param    array   Array of event parameters: connnectionid, hash, username, signature    
  */
  public function fireSignRequestCompleted($param) {
    return $param;
  }

 /**
  * Reports the setup of a TLS session.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid    
  */
  public function fireTLSEstablished($param) {
    return $param;
  }

 /**
  * Requests a pre-shared key for TLS-PSK.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, identity, psk, ciphersuite    
  */
  public function fireTLSPSK($param) {
    return $param;
  }

 /**
  * Reports closure of a TLS session.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid    
  */
  public function fireTLSShutdown($param) {
    return $param;
  }

 /**
  * Fires when the client sends in a write option request.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, name, value    
  */
  public function fireWriteOption($param) {
    return $param;
  }


}

?>
