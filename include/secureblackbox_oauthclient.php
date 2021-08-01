<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - OAuthClient Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_OAuthClient {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_oauthclient_open(SECUREBLACKBOX_OEMKEY_607);
    secureblackbox_oauthclient_register_callback($this->handle, 1, array($this, 'fireCertificateValidate'));
    secureblackbox_oauthclient_register_callback($this->handle, 2, array($this, 'fireError'));
    secureblackbox_oauthclient_register_callback($this->handle, 3, array($this, 'fireExternalSign'));
    secureblackbox_oauthclient_register_callback($this->handle, 4, array($this, 'fireLaunchBrowser'));
    secureblackbox_oauthclient_register_callback($this->handle, 5, array($this, 'fireWait'));
  }
  
  public function __destruct() {
    secureblackbox_oauthclient_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_oauthclient_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_oauthclient_get_last_error_code($this->handle);
  }

 /**
  * Performs user authorization and gets an access token.
  *
  * @access   public
  */
  public function doAuthorize() {
    $ret = secureblackbox_oauthclient_do_authorize($this->handle);
		$err = 0;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_oauthclient_do_config($this->handle, $configurationstring);
		$err = secureblackbox_oauthclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_oauthclient_get($this->handle, 0);
  }
 /**
  * Contains the access token.
  *
  * @access   public
  */
  public function getAccessToken() {
    return secureblackbox_oauthclient_get($this->handle, 1 );
  }
 /**
  * Contains the access token.
  *
  * @access   public
  * @param    string   value
  */
  public function setAccessToken($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the URL of the authorization server.
  *
  * @access   public
  */
  public function getAuthURL() {
    return secureblackbox_oauthclient_get($this->handle, 2 );
  }
 /**
  * Specifies the URL of the authorization server.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthURL($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether access token should be automatically refreshed.
  *
  * @access   public
  */
  public function getAutoRefresh() {
    return secureblackbox_oauthclient_get($this->handle, 3 );
  }
 /**
  * Specifies whether access token should be automatically refreshed.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAutoRefresh($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  */
  public function getBlockedCertCount() {
    return secureblackbox_oauthclient_get($this->handle, 4 );
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setBlockedCertCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getBlockedCertBytes($blockedcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 5 , $blockedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getBlockedCertHandle($blockedcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 6 , $blockedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setBlockedCertHandle($blockedcertindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 6, $value , $blockedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the ClientCert arrays.
  *
  * @access   public
  */
  public function getClientCertCount() {
    return secureblackbox_oauthclient_get($this->handle, 7 );
  }
 /**
  * The number of records in the ClientCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setClientCertCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getClientCertBytes($clientcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 8 , $clientcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getClientCertHandle($clientcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 9 , $clientcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setClientCertHandle($clientcertindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 9, $value , $clientcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Client ID of the application which needs access to the protected resource.
  *
  * @access   public
  */
  public function getClientID() {
    return secureblackbox_oauthclient_get($this->handle, 10 );
  }
 /**
  * Client ID of the application which needs access to the protected resource.
  *
  * @access   public
  * @param    string   value
  */
  public function setClientID($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Client secret of the application which needs access to the protected resource.
  *
  * @access   public
  */
  public function getClientSecret() {
    return secureblackbox_oauthclient_get($this->handle, 11 );
  }
 /**
  * Client secret of the application which needs access to the protected resource.
  *
  * @access   public
  * @param    string   value
  */
  public function setClientSecret($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether the encryption algorithm used is an AEAD cipher.
  *
  * @access   public
  */
  public function getConnInfoAEADCipher() {
    return secureblackbox_oauthclient_get($this->handle, 12 );
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getConnInfoChainValidationDetails() {
    return secureblackbox_oauthclient_get($this->handle, 13 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getConnInfoChainValidationResult() {
    return secureblackbox_oauthclient_get($this->handle, 14 );
  }


 /**
  * The cipher suite employed by this connection.
  *
  * @access   public
  */
  public function getConnInfoCiphersuite() {
    return secureblackbox_oauthclient_get($this->handle, 15 );
  }


 /**
  * Specifies whether client authentication was performed during this connection.
  *
  * @access   public
  */
  public function getConnInfoClientAuthenticated() {
    return secureblackbox_oauthclient_get($this->handle, 16 );
  }


 /**
  * Specifies whether client authentication was requested during this connection.
  *
  * @access   public
  */
  public function getConnInfoClientAuthRequested() {
    return secureblackbox_oauthclient_get($this->handle, 17 );
  }


 /**
  * Indicates whether the connection has been established fully.
  *
  * @access   public
  */
  public function getConnInfoConnectionEstablished() {
    return secureblackbox_oauthclient_get($this->handle, 18 );
  }


 /**
  * The unique identifier assigned to this connection.
  *
  * @access   public
  */
  public function getConnInfoConnectionID() {
    return secureblackbox_oauthclient_get($this->handle, 19 );
  }


 /**
  * The digest algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getConnInfoDigestAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 20 );
  }


 /**
  * The symmetric encryption algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getConnInfoEncryptionAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 21 );
  }


 /**
  * Indicates whether a TLS connection uses a reduced-strength exportable cipher.
  *
  * @access   public
  */
  public function getConnInfoExportable() {
    return secureblackbox_oauthclient_get($this->handle, 22 );
  }


 /**
  * The key exchange algorithm used in a TLS-enabled connection.
  *
  * @access   public
  */
  public function getConnInfoKeyExchangeAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 23 );
  }


 /**
  * The length of the key exchange key of a TLS-enabled connection.
  *
  * @access   public
  */
  public function getConnInfoKeyExchangeKeyBits() {
    return secureblackbox_oauthclient_get($this->handle, 24 );
  }


 /**
  * The elliptic curve used in this connection.
  *
  * @access   public
  */
  public function getConnInfoNamedECCurve() {
    return secureblackbox_oauthclient_get($this->handle, 25 );
  }


 /**
  * Indicates whether the chosen ciphersuite provides perfect forward secrecy (PFS).
  *
  * @access   public
  */
  public function getConnInfoPFSCipher() {
    return secureblackbox_oauthclient_get($this->handle, 26 );
  }


 /**
  * A hint professed by the server to help the client select the PSK identity to use.
  *
  * @access   public
  */
  public function getConnInfoPreSharedIdentityHint() {
    return secureblackbox_oauthclient_get($this->handle, 27 );
  }


 /**
  * The length of the public key.
  *
  * @access   public
  */
  public function getConnInfoPublicKeyBits() {
    return secureblackbox_oauthclient_get($this->handle, 28 );
  }


 /**
  * Indicates whether a TLS-enabled connection was spawned from another TLS connection.
  *
  * @access   public
  */
  public function getConnInfoResumedSession() {
    return secureblackbox_oauthclient_get($this->handle, 29 );
  }


 /**
  * Indicates whether TLS or SSL is enabled for this connection.
  *
  * @access   public
  */
  public function getConnInfoSecureConnection() {
    return secureblackbox_oauthclient_get($this->handle, 30 );
  }


 /**
  * Indicates whether server authentication was performed during a TLS-enabled connection.
  *
  * @access   public
  */
  public function getConnInfoServerAuthenticated() {
    return secureblackbox_oauthclient_get($this->handle, 31 );
  }


 /**
  * The signature algorithm used in a TLS handshake.
  *
  * @access   public
  */
  public function getConnInfoSignatureAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 32 );
  }


 /**
  * The block size of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getConnInfoSymmetricBlockSize() {
    return secureblackbox_oauthclient_get($this->handle, 33 );
  }


 /**
  * The key length of the symmetric algorithm used.
  *
  * @access   public
  */
  public function getConnInfoSymmetricKeyBits() {
    return secureblackbox_oauthclient_get($this->handle, 34 );
  }


 /**
  * The total number of bytes received over this connection.
  *
  * @access   public
  */
  public function getConnInfoTotalBytesReceived() {
    return secureblackbox_oauthclient_get($this->handle, 35 );
  }


 /**
  * The total number of bytes sent over this connection.
  *
  * @access   public
  */
  public function getConnInfoTotalBytesSent() {
    return secureblackbox_oauthclient_get($this->handle, 36 );
  }


 /**
  * Contains the server certificate's chain validation log.
  *
  * @access   public
  */
  public function getConnInfoValidationLog() {
    return secureblackbox_oauthclient_get($this->handle, 37 );
  }


 /**
  * Indicates the version of SSL/TLS protocol negotiated during this connection.
  *
  * @access   public
  */
  public function getConnInfoVersion() {
    return secureblackbox_oauthclient_get($this->handle, 38 );
  }


 /**
  * The number of records in the CustomParams arrays.
  *
  * @access   public
  */
  public function getCustomParamCount() {
    return secureblackbox_oauthclient_get($this->handle, 39 );
  }
 /**
  * The number of records in the CustomParams arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setCustomParamCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 39, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name element in a (name, value) pair.
  *
  * @access   public
  */
  public function getCustomParamsName($customparamindex) {
    return secureblackbox_oauthclient_get($this->handle, 40 , $customparamindex);
  }
 /**
  * The name element in a (name, value) pair.
  *
  * @access   public
  * @param    string   value
  */
  public function setCustomParamsName($customparamindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 40, $value , $customparamindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The value element in a (name, value) pair.
  *
  * @access   public
  */
  public function getCustomParamsValue($customparamindex) {
    return secureblackbox_oauthclient_get($this->handle, 41 , $customparamindex);
  }
 /**
  * The value element in a (name, value) pair.
  *
  * @access   public
  * @param    string   value
  */
  public function setCustomParamsValue($customparamindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 41, $value , $customparamindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The expiration time of access token.
  *
  * @access   public
  */
  public function getExpiresAt() {
    return secureblackbox_oauthclient_get($this->handle, 42 );
  }
 /**
  * The expiration time of access token.
  *
  * @access   public
  * @param    string   value
  */
  public function setExpiresAt($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 42, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns access token lifetime in seconds.
  *
  * @access   public
  */
  public function getExpiresIn() {
    return secureblackbox_oauthclient_get($this->handle, 43 );
  }


 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_oauthclient_get($this->handle, 44 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 44, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_oauthclient_get($this->handle, 45 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 45, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_oauthclient_get($this->handle, 46 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 46, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 47 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_oauthclient_get($this->handle, 48 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 48, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_oauthclient_get($this->handle, 49 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 49, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_oauthclient_get($this->handle, 50 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 50, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_oauthclient_get($this->handle, 51 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 51, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_oauthclient_get($this->handle, 52 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 52, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The web page showed to the user by the class on authorization failure.
  *
  * @access   public
  */
  public function getFailureResponse() {
    return secureblackbox_oauthclient_get($this->handle, 53 );
  }
 /**
  * The web page showed to the user by the class on authorization failure.
  *
  * @access   public
  * @param    string   value
  */
  public function setFailureResponse($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 53, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies which protocol flow should be used to authorize the user.
  *
  * @access   public
  */
  public function getGrantType() {
    return secureblackbox_oauthclient_get($this->handle, 54 );
  }
 /**
  * Specifies which protocol flow should be used to authorize the user.
  *
  * @access   public
  * @param    int   value
  */
  public function setGrantType($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 54, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the keep-alive handling policy.
  *
  * @access   public
  */
  public function getKeepAlivePolicy() {
    return secureblackbox_oauthclient_get($this->handle, 55 );
  }
 /**
  * Defines the keep-alive handling policy.
  *
  * @access   public
  * @param    int   value
  */
  public function setKeepAlivePolicy($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 55, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_oauthclient_get($this->handle, 56 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 56, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_oauthclient_get($this->handle, 57 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_oauthclient_get($this->handle, 58 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 58, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  */
  public function getKnownCRLCount() {
    return secureblackbox_oauthclient_get($this->handle, 59 );
  }
 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCRLCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 59, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getKnownCRLBytes($knowncrlindex) {
    return secureblackbox_oauthclient_get($this->handle, 60 , $knowncrlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCRLHandle($knowncrlindex) {
    return secureblackbox_oauthclient_get($this->handle, 61 , $knowncrlindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCRLHandle($knowncrlindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 61, $value , $knowncrlindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  */
  public function getKnownOCSPCount() {
    return secureblackbox_oauthclient_get($this->handle, 62 );
  }
 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownOCSPCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 62, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getKnownOCSPBytes($knownocspindex) {
    return secureblackbox_oauthclient_get($this->handle, 63 , $knownocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownOCSPHandle($knownocspindex) {
    return secureblackbox_oauthclient_get($this->handle, 64 , $knownocspindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownOCSPHandle($knownocspindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 64, $value , $knownocspindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The connecting user's authentication password.
  *
  * @access   public
  */
  public function getPassword() {
    return secureblackbox_oauthclient_get($this->handle, 65 );
  }
 /**
  * The connecting user's authentication password.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 65, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxyAddress() {
    return secureblackbox_oauthclient_get($this->handle, 66 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyAddress($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 66, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxyAuthentication() {
    return secureblackbox_oauthclient_get($this->handle, 67 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyAuthentication($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 67, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxyPassword() {
    return secureblackbox_oauthclient_get($this->handle, 68 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyPassword($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 68, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxyPort() {
    return secureblackbox_oauthclient_get($this->handle, 69 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyPort($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 69, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxyProxyType() {
    return secureblackbox_oauthclient_get($this->handle, 70 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyProxyType($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 70, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxyRequestHeaders() {
    return secureblackbox_oauthclient_get($this->handle, 71 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyRequestHeaders($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxyResponseBody() {
    return secureblackbox_oauthclient_get($this->handle, 72 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseBody($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 72, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxyResponseHeaders() {
    return secureblackbox_oauthclient_get($this->handle, 73 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseHeaders($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxyUseIPv6() {
    return secureblackbox_oauthclient_get($this->handle, 74 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseIPv6($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxyUseProxy() {
    return secureblackbox_oauthclient_get($this->handle, 75 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseProxy($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxyUsername() {
    return secureblackbox_oauthclient_get($this->handle, 76 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyUsername($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The URL where the user is redirected after authorization.
  *
  * @access   public
  */
  public function getRedirectURL() {
    return secureblackbox_oauthclient_get($this->handle, 77 );
  }
 /**
  * The URL where the user is redirected after authorization.
  *
  * @access   public
  * @param    string   value
  */
  public function setRedirectURL($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The refresh token, to be used to automatically obtain new access token.
  *
  * @access   public
  */
  public function getRefreshToken() {
    return secureblackbox_oauthclient_get($this->handle, 78 );
  }
 /**
  * The refresh token, to be used to automatically obtain new access token.
  *
  * @access   public
  * @param    string   value
  */
  public function setRefreshToken($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The scope of the request to be authorized.
  *
  * @access   public
  */
  public function getScope() {
    return secureblackbox_oauthclient_get($this->handle, 79 );
  }
 /**
  * The scope of the request to be authorized.
  *
  * @access   public
  * @param    string   value
  */
  public function setScope($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the ServerCert arrays.
  *
  * @access   public
  */
  public function getServerCertCount() {
    return secureblackbox_oauthclient_get($this->handle, 80 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getServerCertBytes($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 81 , $servercertindex);
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getServerCertCAKeyID($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 82 , $servercertindex);
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getServerCertFingerprint($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 83 , $servercertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getServerCertHandle($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 84 , $servercertindex);
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getServerCertIssuer($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 85 , $servercertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getServerCertIssuerRDN($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 86 , $servercertindex);
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getServerCertKeyAlgorithm($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 87 , $servercertindex);
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getServerCertKeyBits($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 88 , $servercertindex);
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getServerCertKeyFingerprint($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 89 , $servercertindex);
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getServerCertKeyUsage($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 90 , $servercertindex);
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getServerCertPublicKeyBytes($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 91 , $servercertindex);
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getServerCertSelfSigned($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 92 , $servercertindex);
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getServerCertSerialNumber($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 93 , $servercertindex);
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getServerCertSigAlgorithm($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 94 , $servercertindex);
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getServerCertSubject($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 95 , $servercertindex);
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getServerCertSubjectKeyID($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 96 , $servercertindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getServerCertSubjectRDN($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 97 , $servercertindex);
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getServerCertValidFrom($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 98 , $servercertindex);
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getServerCertValidTo($servercertindex) {
    return secureblackbox_oauthclient_get($this->handle, 99 , $servercertindex);
  }


 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_oauthclient_get($this->handle, 100 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 100, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_oauthclient_get($this->handle, 101 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 101, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_oauthclient_get($this->handle, 102 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 102, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_oauthclient_get($this->handle, 103 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 103, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_oauthclient_get($this->handle, 104 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 104, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_oauthclient_get($this->handle, 105 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 105, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_oauthclient_get($this->handle, 106 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 106, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_oauthclient_get($this->handle, 107 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 107, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_oauthclient_get($this->handle, 108 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 108, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_oauthclient_get($this->handle, 109 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 109, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_oauthclient_get($this->handle, 110 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 110, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the state parameter of the authorization request or response.
  *
  * @access   public
  */
  public function getState() {
    return secureblackbox_oauthclient_get($this->handle, 111 );
  }
 /**
  * Specifies the state parameter of the authorization request or response.
  *
  * @access   public
  * @param    string   value
  */
  public function setState($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 111, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The web page showed to the user by the class on authorization success.
  *
  * @access   public
  */
  public function getSuccessResponse() {
    return secureblackbox_oauthclient_get($this->handle, 112 );
  }
 /**
  * The web page showed to the user by the class on authorization success.
  *
  * @access   public
  * @param    string   value
  */
  public function setSuccessResponse($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 112, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies waiting timeout (in milliseconds).
  *
  * @access   public
  */
  public function getTimeout() {
    return secureblackbox_oauthclient_get($this->handle, 113 );
  }
 /**
  * Specifies waiting timeout (in milliseconds).
  *
  * @access   public
  * @param    int   value
  */
  public function setTimeout($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 113, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_oauthclient_get($this->handle, 114 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 114, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_oauthclient_get($this->handle, 115 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 115, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_oauthclient_get($this->handle, 116 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 116, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_oauthclient_get($this->handle, 117 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 117, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_oauthclient_get($this->handle, 118 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 118, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_oauthclient_get($this->handle, 119 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 119, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_oauthclient_get($this->handle, 120 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 120, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_oauthclient_get($this->handle, 121 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 121, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_oauthclient_get($this->handle, 122 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 122, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_oauthclient_get($this->handle, 123 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 123, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_oauthclient_get($this->handle, 124 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 124, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_oauthclient_get($this->handle, 125 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 125, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_oauthclient_get($this->handle, 126 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 126, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_oauthclient_get($this->handle, 127 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 127, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_oauthclient_get($this->handle, 128 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 128, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the access token type.
  *
  * @access   public
  */
  public function getTokenType() {
    return secureblackbox_oauthclient_get($this->handle, 129 );
  }


 /**
  * Specifies the URL of the token endpoint.
  *
  * @access   public
  */
  public function getTokenURL() {
    return secureblackbox_oauthclient_get($this->handle, 130 );
  }
 /**
  * Specifies the URL of the token endpoint.
  *
  * @access   public
  * @param    string   value
  */
  public function setTokenURL($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 130, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  */
  public function getTrustedCertCount() {
    return secureblackbox_oauthclient_get($this->handle, 131 );
  }
 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTrustedCertCount($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 131, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTrustedCertBytes($trustedcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 132 , $trustedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTrustedCertHandle($trustedcertindex) {
    return secureblackbox_oauthclient_get($this->handle, 133 , $trustedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTrustedCertHandle($trustedcertindex, $value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 133, $value , $trustedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The connecting user's username (login name).
  *
  * @access   public
  */
  public function getUsername() {
    return secureblackbox_oauthclient_get($this->handle, 134 );
  }
 /**
  * The connecting user's username (login name).
  *
  * @access   public
  * @param    string   value
  */
  public function setUsername($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 134, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_oauthclient_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_oauthclient_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_oauthclient_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Fires when the server's TLS certificate has to be validated.
  *
  * @access   public
  * @param    array   Array of event parameters: address, accept    
  */
  public function fireCertificateValidate($param) {
    return $param;
  }

 /**
  * Provides information about errors during authorization operations.
  *
  * @access   public
  * @param    array   Array of event parameters: errorcode, description    
  */
  public function fireError($param) {
    return $param;
  }

 /**
  * Handles remote or external signing initiated by the SignExternal method or other source.
  *
  * @access   public
  * @param    array   Array of event parameters: operationid, hashalgorithm, pars, data, signeddata    
  */
  public function fireExternalSign($param) {
    return $param;
  }

 /**
  * Fires to show the login page to the end-user.
  *
  * @access   public
  * @param    array   Array of event parameters: url, handled    
  */
  public function fireLaunchBrowser($param) {
    return $param;
  }

 /**
  * Fired periodically to show how much waiting time is left.
  *
  * @access   public
  * @param    array   Array of event parameters: timeleft, stop    
  */
  public function fireWait($param) {
    return $param;
  }


}

?>
