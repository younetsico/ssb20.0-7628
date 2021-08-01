<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - WebDAVServer Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_WebDAVServer {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_webdavserver_open(SECUREBLACKBOX_OEMKEY_699);
    secureblackbox_webdavserver_register_callback($this->handle, 1, array($this, 'fireAccept'));
    secureblackbox_webdavserver_register_callback($this->handle, 2, array($this, 'fireAuthAttempt'));
    secureblackbox_webdavserver_register_callback($this->handle, 3, array($this, 'fireBeforeRequest'));
    secureblackbox_webdavserver_register_callback($this->handle, 4, array($this, 'fireCertificateValidate'));
    secureblackbox_webdavserver_register_callback($this->handle, 5, array($this, 'fireConnect'));
    secureblackbox_webdavserver_register_callback($this->handle, 6, array($this, 'fireData'));
    secureblackbox_webdavserver_register_callback($this->handle, 7, array($this, 'fireDisconnect'));
    secureblackbox_webdavserver_register_callback($this->handle, 8, array($this, 'fireError'));
    secureblackbox_webdavserver_register_callback($this->handle, 9, array($this, 'fireExternalSign'));
    secureblackbox_webdavserver_register_callback($this->handle, 10, array($this, 'fireFileError'));
    secureblackbox_webdavserver_register_callback($this->handle, 11, array($this, 'fireNotification'));
    secureblackbox_webdavserver_register_callback($this->handle, 12, array($this, 'fireQueryQuota'));
    secureblackbox_webdavserver_register_callback($this->handle, 13, array($this, 'fireTLSEstablished'));
    secureblackbox_webdavserver_register_callback($this->handle, 14, array($this, 'fireTLSPSK'));
    secureblackbox_webdavserver_register_callback($this->handle, 15, array($this, 'fireTLSShutdown'));
  }
  
  public function __destruct() {
    secureblackbox_webdavserver_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_webdavserver_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_webdavserver_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_webdavserver_do_config($this->handle, $configurationstring);
		$err = secureblackbox_webdavserver_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
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
    $ret = secureblackbox_webdavserver_do_dropclient($this->handle, $connectionid, $forced);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enumerates the connected clients.
  *
  * @access   public
  */
  public function doListClients() {
    $ret = secureblackbox_webdavserver_do_listclients($this->handle);
		$err = secureblackbox_webdavserver_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
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
    $ret = secureblackbox_webdavserver_do_pinclient($this->handle, $connectionid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Starts the server.
  *
  * @access   public
  */
  public function doStart() {
    $ret = secureblackbox_webdavserver_do_start($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Stops the server.
  *
  * @access   public
  */
  public function doStop() {
    $ret = secureblackbox_webdavserver_do_stop($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_webdavserver_get($this->handle, 0);
  }
 /**
  * Indicates whether the server is active and is listening to new connections.
  *
  * @access   public
  */
  public function getActive() {
    return secureblackbox_webdavserver_get($this->handle, 1 );
  }


 /**
  * Enables or disables basic authentication.
  *
  * @access   public
  */
  public function getAuthBasic() {
    return secureblackbox_webdavserver_get($this->handle, 2 );
  }
 /**
  * Enables or disables basic authentication.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthBasic($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables digest authentication.
  *
  * @access   public
  */
  public function getAuthDigest() {
    return secureblackbox_webdavserver_get($this->handle, 3 );
  }
 /**
  * Enables or disables digest authentication.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthDigest($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies digest expiration time for digest authentication.
  *
  * @access   public
  */
  public function getAuthDigestExpire() {
    return secureblackbox_webdavserver_get($this->handle, 4 );
  }
 /**
  * Specifies digest expiration time for digest authentication.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthDigestExpire($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies authentication realm for digest and NTLM authentication.
  *
  * @access   public
  */
  public function getAuthRealm() {
    return secureblackbox_webdavserver_get($this->handle, 5 );
  }
 /**
  * Specifies authentication realm for digest and NTLM authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthRealm($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the bound listening port.
  *
  * @access   public
  */
  public function getBoundPort() {
    return secureblackbox_webdavserver_get($this->handle, 6 );
  }


 /**
  * The document root of the server.
  *
  * @access   public
  */
  public function getDocumentRoot() {
    return secureblackbox_webdavserver_get($this->handle, 7 );
  }
 /**
  * The document root of the server.
  *
  * @access   public
  * @param    string   value
  */
  public function setDocumentRoot($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the endpoint where the error originates from.
  *
  * @access   public
  */
  public function getErrorOrigin() {
    return secureblackbox_webdavserver_get($this->handle, 8 );
  }
 /**
  * Indicates the endpoint where the error originates from.
  *
  * @access   public
  * @param    int   value
  */
  public function setErrorOrigin($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The severity of the error that happened.
  *
  * @access   public
  */
  public function getErrorSeverity() {
    return secureblackbox_webdavserver_get($this->handle, 9 );
  }
 /**
  * The severity of the error that happened.
  *
  * @access   public
  * @param    int   value
  */
  public function setErrorSeverity($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_webdavserver_get($this->handle, 10 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_webdavserver_get($this->handle, 11 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_webdavserver_get($this->handle, 12 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 13 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_webdavserver_get($this->handle, 14 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_webdavserver_get($this->handle, 15 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_webdavserver_get($this->handle, 16 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_webdavserver_get($this->handle, 17 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 18 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The host to bind the listening port to.
  *
  * @access   public
  */
  public function getHost() {
    return secureblackbox_webdavserver_get($this->handle, 19 );
  }
 /**
  * The host to bind the listening port to.
  *
  * @access   public
  * @param    string   value
  */
  public function setHost($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies metadata flush timeout.
  *
  * @access   public
  */
  public function getMetadataFlushTimeout() {
    return secureblackbox_webdavserver_get($this->handle, 20 );
  }
 /**
  * Specifies metadata flush timeout.
  *
  * @access   public
  * @param    int   value
  */
  public function setMetadataFlushTimeout($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The document root of the server.
  *
  * @access   public
  */
  public function getMetadataRoot() {
    return secureblackbox_webdavserver_get($this->handle, 21 );
  }
 /**
  * The document root of the server.
  *
  * @access   public
  * @param    string   value
  */
  public function setMetadataRoot($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The client's IP address.
  *
  * @access   public
  */
  public function getPinnedClientAddress() {
    return secureblackbox_webdavserver_get($this->handle, 22 );
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getPinnedClientChainValidationDetails() {
    return secureblackbox_webdavserver_get($this->handle, 23 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getPinnedClientChainValidationResult() {
    return secureblackbox_webdavserver_get($this->handle, 24 );
  }


 /**
  * The cipher suite employed by this connection.
  *
  * @access   public
  */
  public function getPinnedClientCiphersuite() {
    return secureblackbox_webdavserver_get($this->handle, 25 );
  }


 /**
  * Specifies whether client authentication was performed during this connection.
  *
  * @access   public
  */
  public function getPinnedClientClientAuthenticated() {
    return secureblackbox_webdavserver_get($this->handle, 26 );
  }


 /**
  * The digest algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientDigestAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 27 );
  }


 /**
  * The symmetric encryption algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientEncryptionAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 28 );
  }


 /**
  * The client connection's unique identifier.
  *
  * @access   public
  */
  public function getPinnedClientID() {
    return secureblackbox_webdavserver_get($this->handle, 29 );
  }


 /**
  * The key exchange algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientKeyExchangeAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 30 );
  }


 /**
  * The length of the key exchange key of a TLS-enabled connection.
  *
  * @access   public
  */
  public function getPinnedClientKeyExchangeKeyBits() {
    return secureblackbox_webdavserver_get($this->handle, 31 );
  }


 /**
  * The elliptic curve used in this connection.
  *
  * @access   public
  */
  public function getPinnedClientNamedECCurve() {
    return secureblackbox_webdavserver_get($this->handle, 32 );
  }


 /**
  * Indicates whether the chosen ciphersuite provides perfect forward secrecy (PFS).
  *
  * @access   public
  */
  public function getPinnedClientPFSCipher() {
    return secureblackbox_webdavserver_get($this->handle, 33 );
  }


 /**
  * The remote port of the client connection.
  *
  * @access   public
  */
  public function getPinnedClientPort() {
    return secureblackbox_webdavserver_get($this->handle, 34 );
  }


 /**
  * The length of the public key.
  *
  * @access   public
  */
  public function getPinnedClientPublicKeyBits() {
    return secureblackbox_webdavserver_get($this->handle, 35 );
  }


 /**
  * Indicates whether a TLS-enabled connection was spawned from another TLS connection.
  *
  * @access   public
  */
  public function getPinnedClientResumedSession() {
    return secureblackbox_webdavserver_get($this->handle, 36 );
  }


 /**
  * Indicates whether TLS or SSL is enabled for this connection.
  *
  * @access   public
  */
  public function getPinnedClientSecureConnection() {
    return secureblackbox_webdavserver_get($this->handle, 37 );
  }


 /**
  * The signature algorithm used in a TLS handshake.
  *
  * @access   public
  */
  public function getPinnedClientSignatureAlgorithm() {
    return secureblackbox_webdavserver_get($this->handle, 38 );
  }


 /**
  * The block size of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getPinnedClientSymmetricBlockSize() {
    return secureblackbox_webdavserver_get($this->handle, 39 );
  }


 /**
  * The key length of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getPinnedClientSymmetricKeyBits() {
    return secureblackbox_webdavserver_get($this->handle, 40 );
  }


 /**
  * The total number of bytes received over this connection.
  *
  * @access   public
  */
  public function getPinnedClientTotalBytesReceived() {
    return secureblackbox_webdavserver_get($this->handle, 41 );
  }


 /**
  * The total number of bytes sent over this connection.
  *
  * @access   public
  */
  public function getPinnedClientTotalBytesSent() {
    return secureblackbox_webdavserver_get($this->handle, 42 );
  }


 /**
  * Contains the server certificate's chain validation log.
  *
  * @access   public
  */
  public function getPinnedClientValidationLog() {
    return secureblackbox_webdavserver_get($this->handle, 43 );
  }


 /**
  * Indicates the version of SSL/TLS protocol negotiated during this connection.
  *
  * @access   public
  */
  public function getPinnedClientVersion() {
    return secureblackbox_webdavserver_get($this->handle, 44 );
  }


 /**
  * The number of records in the PinnedClientCert arrays.
  *
  * @access   public
  */
  public function getPinnedClientCertCount() {
    return secureblackbox_webdavserver_get($this->handle, 45 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getPinnedClientCertBytes($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 46 , $pinnedclientcertindex);
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getPinnedClientCertCA($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 47 , $pinnedclientcertindex);
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getPinnedClientCertCAKeyID($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 48 , $pinnedclientcertindex);
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getPinnedClientCertCRLDistributionPoints($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 49 , $pinnedclientcertindex);
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getPinnedClientCertCurve($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 50 , $pinnedclientcertindex);
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertFingerprint($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 51 , $pinnedclientcertindex);
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertFriendlyName($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 52 , $pinnedclientcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getPinnedClientCertHandle($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 53 , $pinnedclientcertindex);
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getPinnedClientCertHashAlgorithm($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 54 , $pinnedclientcertindex);
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getPinnedClientCertIssuer($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 55 , $pinnedclientcertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getPinnedClientCertIssuerRDN($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 56 , $pinnedclientcertindex);
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyAlgorithm($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 57 , $pinnedclientcertindex);
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyBits($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 58 , $pinnedclientcertindex);
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyFingerprint($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 59 , $pinnedclientcertindex);
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyUsage($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 60 , $pinnedclientcertindex);
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getPinnedClientCertKeyValid($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 61 , $pinnedclientcertindex);
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getPinnedClientCertOCSPLocations($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 62 , $pinnedclientcertindex);
  }


 /**
  * Returns the origin of this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertOrigin($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 63 , $pinnedclientcertindex);
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getPinnedClientCertPolicyIDs($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 64 , $pinnedclientcertindex);
  }


 /**
  * Contains the certificate's private key.
  *
  * @access   public
  */
  public function getPinnedClientCertPrivateKeyBytes($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 65 , $pinnedclientcertindex);
  }


 /**
  * Indicates whether the certificate has an associated private key.
  *
  * @access   public
  */
  public function getPinnedClientCertPrivateKeyExists($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 66 , $pinnedclientcertindex);
  }


 /**
  * Indicates whether the private key is extractable.
  *
  * @access   public
  */
  public function getPinnedClientCertPrivateKeyExtractable($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 67 , $pinnedclientcertindex);
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getPinnedClientCertPublicKeyBytes($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 68 , $pinnedclientcertindex);
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getPinnedClientCertSelfSigned($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 69 , $pinnedclientcertindex);
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getPinnedClientCertSerialNumber($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 70 , $pinnedclientcertindex);
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getPinnedClientCertSigAlgorithm($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 71 , $pinnedclientcertindex);
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getPinnedClientCertSubject($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 72 , $pinnedclientcertindex);
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getPinnedClientCertSubjectKeyID($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 73 , $pinnedclientcertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getPinnedClientCertSubjectRDN($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 74 , $pinnedclientcertindex);
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getPinnedClientCertValidFrom($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 75 , $pinnedclientcertindex);
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getPinnedClientCertValidTo($pinnedclientcertindex) {
    return secureblackbox_webdavserver_get($this->handle, 76 , $pinnedclientcertindex);
  }


 /**
  * Specifies the port number to listen for connections on.
  *
  * @access   public
  */
  public function getPort() {
    return secureblackbox_webdavserver_get($this->handle, 77 );
  }
 /**
  * Specifies the port number to listen for connections on.
  *
  * @access   public
  * @param    int   value
  */
  public function setPort($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the lower limit of the listening port range for incoming connections.
  *
  * @access   public
  */
  public function getPortRangeFrom() {
    return secureblackbox_webdavserver_get($this->handle, 78 );
  }
 /**
  * Specifies the lower limit of the listening port range for incoming connections.
  *
  * @access   public
  * @param    int   value
  */
  public function setPortRangeFrom($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the upper limit of the listening port range for incoming connections.
  *
  * @access   public
  */
  public function getPortRangeTo() {
    return secureblackbox_webdavserver_get($this->handle, 79 );
  }
 /**
  * Specifies the upper limit of the listening port range for incoming connections.
  *
  * @access   public
  * @param    int   value
  */
  public function setPortRangeTo($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the ServerCert arrays.
  *
  * @access   public
  */
  public function getServerCertCount() {
    return secureblackbox_webdavserver_get($this->handle, 80 );
  }
 /**
  * The number of records in the ServerCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setServerCertCount($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getServerCertBytes($servercertindex) {
    return secureblackbox_webdavserver_get($this->handle, 81 , $servercertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getServerCertHandle($servercertindex) {
    return secureblackbox_webdavserver_get($this->handle, 82 , $servercertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setServerCertHandle($servercertindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 82, $value , $servercertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_webdavserver_get($this->handle, 83 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 83, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_webdavserver_get($this->handle, 84 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 84, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_webdavserver_get($this->handle, 85 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 85, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_webdavserver_get($this->handle, 86 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_webdavserver_get($this->handle, 87 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 87, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_webdavserver_get($this->handle, 88 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 88, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_webdavserver_get($this->handle, 89 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 89, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_webdavserver_get($this->handle, 90 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_webdavserver_get($this->handle, 91 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 91, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_webdavserver_get($this->handle, 92 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 92, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_webdavserver_get($this->handle, 93 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 93, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_webdavserver_get($this->handle, 94 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 94, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_webdavserver_get($this->handle, 95 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 95, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_webdavserver_get($this->handle, 96 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 96, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_webdavserver_get($this->handle, 97 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 97, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_webdavserver_get($this->handle, 98 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 98, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_webdavserver_get($this->handle, 99 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 99, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_webdavserver_get($this->handle, 100 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 100, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_webdavserver_get($this->handle, 101 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 101, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_webdavserver_get($this->handle, 102 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 102, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_webdavserver_get($this->handle, 103 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 103, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the User arrays.
  *
  * @access   public
  */
  public function getUserCount() {
    return secureblackbox_webdavserver_get($this->handle, 104 );
  }
 /**
  * The number of records in the User arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserCount($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 104, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  */
  public function getUserAssociatedData($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 105 , $userindex);
  }
 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserAssociatedData($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 105, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  */
  public function getUserBasePath($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 106 , $userindex);
  }
 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserBasePath($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 106, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's certificate.
  *
  * @access   public
  */
  public function getUserCert($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 107 , $userindex);
  }
 /**
  * Contains the user's certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserCert($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 107, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  */
  public function getUserData($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 108 , $userindex);
  }
 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserData($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 108, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getUserHandle($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 109 , $userindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setUserHandle($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 109, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  */
  public function getUserHashAlgorithm($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 110 , $userindex);
  }
 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserHashAlgorithm($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 110, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  */
  public function getUserIncomingSpeedLimit($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 111 , $userindex);
  }
 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserIncomingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 111, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm used to generate one-time passwords (OTP) for this user, either HOTP (Hash-based OTP) or TOTP (Time-based OTP).
  *
  * @access   public
  */
  public function getUserOtpAlgorithm($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 112 , $userindex);
  }
 /**
  * The algorithm used to generate one-time passwords (OTP) for this user, either HOTP (Hash-based OTP) or TOTP (Time-based OTP).
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOtpAlgorithm($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 112, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user's time interval (TOTP) or Counter (HOTP).
  *
  * @access   public
  */
  public function getUserOtpValue($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 113 , $userindex);
  }
 /**
  * The user's time interval (TOTP) or Counter (HOTP).
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOtpValue($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 113, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  */
  public function getUserOutgoingSpeedLimit($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 114 , $userindex);
  }
 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOutgoingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 114, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user's authentication password.
  *
  * @access   public
  */
  public function getUserPassword($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 115 , $userindex);
  }
 /**
  * The user's authentication password.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserPassword($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 115, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the length of the user's OTP password.
  *
  * @access   public
  */
  public function getUserPasswordLen($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 116 , $userindex);
  }
 /**
  * Specifies the length of the user's OTP password.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserPasswordLen($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 116, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  */
  public function getUserSharedSecret($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 117 , $userindex);
  }
 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserSharedSecret($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 117, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's SSH key.
  *
  * @access   public
  */
  public function getUserSSHKey($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 118 , $userindex);
  }
 /**
  * Contains the user's SSH key.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserSSHKey($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 118, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The registered name (login) of the user.
  *
  * @access   public
  */
  public function getUserUsername($userindex) {
    return secureblackbox_webdavserver_get($this->handle, 119 , $userindex);
  }
 /**
  * The registered name (login) of the user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserUsername($userindex, $value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 119, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables the TLS requirement.
  *
  * @access   public
  */
  public function getUseTLS() {
    return secureblackbox_webdavserver_get($this->handle, 120 );
  }
 /**
  * Enables or disables the TLS requirement.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseTLS($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 120, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the web site name to use in the certificate.
  *
  * @access   public
  */
  public function getWebsiteName() {
    return secureblackbox_webdavserver_get($this->handle, 121 );
  }
 /**
  * Specifies the web site name to use in the certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setWebsiteName($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 121, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_webdavserver_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_webdavserver_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_webdavserver_get_last_error($this->handle));
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
  * Fires before a DAV request is processed.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, httpmethod, url, accept    
  */
  public function fireBeforeRequest($param) {
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
  * Supplies a data chunk received from a client.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, buffer    
  */
  public function fireData($param) {
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
  * Reports a file access error to the application.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, filename, errorcode    
  */
  public function fireFileError($param) {
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
  * Reflects a quota enquiry by a client.
  *
  * @access   public
  * @param    array   Array of event parameters: connectionid, username, available, used    
  */
  public function fireQueryQuota($param) {
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


}

?>
