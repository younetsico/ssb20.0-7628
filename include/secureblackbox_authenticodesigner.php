<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - AuthenticodeSigner Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_AuthenticodeSigner {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_authenticodesigner_open(SECUREBLACKBOX_OEMKEY_218);
    secureblackbox_authenticodesigner_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_authenticodesigner_register_callback($this->handle, 2, array($this, 'fireExternalSign'));
    secureblackbox_authenticodesigner_register_callback($this->handle, 3, array($this, 'fireNotification'));
    secureblackbox_authenticodesigner_register_callback($this->handle, 4, array($this, 'fireStart'));
    secureblackbox_authenticodesigner_register_callback($this->handle, 5, array($this, 'fireTLSCertValidate'));
  }
  
  public function __destruct() {
    secureblackbox_authenticodesigner_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_authenticodesigner_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_authenticodesigner_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_authenticodesigner_do_config($this->handle, $configurationstring);
		$err = secureblackbox_authenticodesigner_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Extracts user data from the DC signing service response.
  *
  * @access   public
  * @param    string    asyncreply
  */
  public function doExtractAsyncData($asyncreply) {
    $ret = secureblackbox_authenticodesigner_do_extractasyncdata($this->handle, $asyncreply);
		$err = secureblackbox_authenticodesigner_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Calculates and adds a signature to the executable.
  *
  * @access   public
  */
  public function doSign() {
    $ret = secureblackbox_authenticodesigner_do_sign($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Initiates asynchronous (DC) signing.
  *
  * @access   public
  */
  public function doSignAsyncBegin() {
    $ret = secureblackbox_authenticodesigner_do_signasyncbegin($this->handle);
		$err = secureblackbox_authenticodesigner_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Completes asynchronous signing.
  *
  * @access   public
  * @param    string    asyncreply
  */
  public function doSignAsyncEnd($asyncreply) {
    $ret = secureblackbox_authenticodesigner_do_signasyncend($this->handle, $asyncreply);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs the document using an external signing facility.
  *
  * @access   public
  */
  public function doSignExternal() {
    $ret = secureblackbox_authenticodesigner_do_signexternal($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_authenticodesigner_get($this->handle, 0);
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  */
  public function getBlockedCertCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 1 );
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setBlockedCertCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getBlockedCertBytes($blockedcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 2 , $blockedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getBlockedCertHandle($blockedcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 3 , $blockedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setBlockedCertHandle($blockedcertindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 3, $value , $blockedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signing time from the signer's computer.
  *
  * @access   public
  */
  public function getClaimedSigningTime() {
    return secureblackbox_authenticodesigner_get($this->handle, 4 );
  }
 /**
  * The signing time from the signer's computer.
  *
  * @access   public
  * @param    string   value
  */
  public function setClaimedSigningTime($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_authenticodesigner_get($this->handle, 5 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_authenticodesigner_get($this->handle, 6 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_authenticodesigner_get($this->handle, 7 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_authenticodesigner_get($this->handle, 8 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_authenticodesigner_get($this->handle, 9 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_authenticodesigner_get($this->handle, 10 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_authenticodesigner_get($this->handle, 11 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_authenticodesigner_get($this->handle, 12 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_authenticodesigner_get($this->handle, 13 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash algorithm to be used for signing.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return secureblackbox_authenticodesigner_get($this->handle, 14 );
  }
 /**
  * The hash algorithm to be used for signing.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashAlgorithm($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  */
  public function getIgnoreChainValidationErrors() {
    return secureblackbox_authenticodesigner_get($this->handle, 15 );
  }
 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIgnoreChainValidationErrors($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  */
  public function getInputBytes() {
    return secureblackbox_authenticodesigner_get($this->handle, 16 );
  }
 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputBytes($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A path to the executable to be signed.
  *
  * @access   public
  */
  public function getInputFile() {
    return secureblackbox_authenticodesigner_get($this->handle, 17 );
  }
 /**
  * A path to the executable to be signed.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 18 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 19 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 20 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 20, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  */
  public function getKnownCRLCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 21 );
  }
 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCRLCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getKnownCRLBytes($knowncrlindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 22 , $knowncrlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCRLHandle($knowncrlindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 23 , $knowncrlindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCRLHandle($knowncrlindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 23, $value , $knowncrlindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  */
  public function getKnownOCSPCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 24 );
  }
 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownOCSPCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getKnownOCSPBytes($knownocspindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 25 , $knownocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownOCSPHandle($knownocspindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 26 , $knownocspindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownOCSPHandle($knownocspindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 26, $value , $knownocspindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  */
  public function getOfflineMode() {
    return secureblackbox_authenticodesigner_get($this->handle, 27 );
  }
 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOfflineMode($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to read the output the class object has produced.
  *
  * @access   public
  */
  public function getOutputBytes() {
    return secureblackbox_authenticodesigner_get($this->handle, 28 );
  }


 /**
  * The file to save the signed executable to.
  *
  * @access   public
  */
  public function getOutputFile() {
    return secureblackbox_authenticodesigner_get($this->handle, 29 );
  }
 /**
  * The file to save the signed executable to.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  */
  public function getProfile() {
    return secureblackbox_authenticodesigner_get($this->handle, 30 );
  }
 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setProfile($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxyAddress() {
    return secureblackbox_authenticodesigner_get($this->handle, 31 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyAddress($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 31, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxyAuthentication() {
    return secureblackbox_authenticodesigner_get($this->handle, 32 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyAuthentication($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxyPassword() {
    return secureblackbox_authenticodesigner_get($this->handle, 33 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyPassword($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 33, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxyPort() {
    return secureblackbox_authenticodesigner_get($this->handle, 34 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyPort($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 34, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxyProxyType() {
    return secureblackbox_authenticodesigner_get($this->handle, 35 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyProxyType($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxyRequestHeaders() {
    return secureblackbox_authenticodesigner_get($this->handle, 36 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyRequestHeaders($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxyResponseBody() {
    return secureblackbox_authenticodesigner_get($this->handle, 37 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseBody($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxyResponseHeaders() {
    return secureblackbox_authenticodesigner_get($this->handle, 38 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseHeaders($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 38, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxyUseIPv6() {
    return secureblackbox_authenticodesigner_get($this->handle, 39 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseIPv6($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 39, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxyUseProxy() {
    return secureblackbox_authenticodesigner_get($this->handle, 40 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseProxy($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 40, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxyUsername() {
    return secureblackbox_authenticodesigner_get($this->handle, 41 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyUsername($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 41, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to remove any existing signatures before signing.
  *
  * @access   public
  */
  public function getRemoveExistingSignatures() {
    return secureblackbox_authenticodesigner_get($this->handle, 42 );
  }
 /**
  * Specifies whether to remove any existing signatures before signing.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setRemoveExistingSignatures($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 42, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getRevocationCheck() {
    return secureblackbox_authenticodesigner_get($this->handle, 43 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setRevocationCheck($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 43, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets human-readable signature description.
  *
  * @access   public
  */
  public function getSignatureDescription() {
    return secureblackbox_authenticodesigner_get($this->handle, 44 );
  }
 /**
  * Sets human-readable signature description.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignatureDescription($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 44, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets the URL to include in the signature.
  *
  * @access   public
  */
  public function getSignatureURL() {
    return secureblackbox_authenticodesigner_get($this->handle, 45 );
  }
 /**
  * Sets the URL to include in the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setSignatureURL($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 45, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_authenticodesigner_get($this->handle, 46 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_authenticodesigner_get($this->handle, 47 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningCertHandle($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  */
  public function getSigningChainCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 48 );
  }
 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setSigningChainCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 48, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningChainBytes($signingchainindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 49 , $signingchainindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningChainHandle($signingchainindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 50 , $signingchainindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningChainHandle($signingchainindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 50, $value , $signingchainindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_authenticodesigner_get($this->handle, 51 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 51, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_authenticodesigner_get($this->handle, 52 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 52, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_authenticodesigner_get($this->handle, 53 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 53, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_authenticodesigner_get($this->handle, 54 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 54, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_authenticodesigner_get($this->handle, 55 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 55, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_authenticodesigner_get($this->handle, 56 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 56, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_authenticodesigner_get($this->handle, 57 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 57, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_authenticodesigner_get($this->handle, 58 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 58, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_authenticodesigner_get($this->handle, 59 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 59, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_authenticodesigner_get($this->handle, 60 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 60, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_authenticodesigner_get($this->handle, 61 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 61, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets the signature statement type.
  *
  * @access   public
  */
  public function getStatementType() {
    return secureblackbox_authenticodesigner_get($this->handle, 62 );
  }
 /**
  * Sets the signature statement type.
  *
  * @access   public
  * @param    int   value
  */
  public function setStatementType($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 62, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The address of the timestamping server.
  *
  * @access   public
  */
  public function getTimestampServer() {
    return secureblackbox_authenticodesigner_get($this->handle, 63 );
  }
 /**
  * The address of the timestamping server.
  *
  * @access   public
  * @param    string   value
  */
  public function setTimestampServer($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 63, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets the signature timestamp type.
  *
  * @access   public
  */
  public function getTimestampType() {
    return secureblackbox_authenticodesigner_get($this->handle, 64 );
  }
 /**
  * Sets the signature timestamp type.
  *
  * @access   public
  * @param    int   value
  */
  public function setTimestampType($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 64, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TLSClientCert arrays.
  *
  * @access   public
  */
  public function getTLSClientCertCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 65 );
  }
 /**
  * The number of records in the TLSClientCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSClientCertCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 65, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTLSClientCertBytes($tlsclientcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 66 , $tlsclientcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTLSClientCertHandle($tlsclientcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 67 , $tlsclientcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTLSClientCertHandle($tlsclientcertindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 67, $value , $tlsclientcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TLSServerCert arrays.
  *
  * @access   public
  */
  public function getTLSServerCertCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 68 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTLSServerCertBytes($tlsservercertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 69 , $tlsservercertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTLSServerCertHandle($tlsservercertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 70 , $tlsservercertindex);
  }


 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_authenticodesigner_get($this->handle, 71 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_authenticodesigner_get($this->handle, 72 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 72, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_authenticodesigner_get($this->handle, 73 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_authenticodesigner_get($this->handle, 74 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_authenticodesigner_get($this->handle, 75 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_authenticodesigner_get($this->handle, 76 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_authenticodesigner_get($this->handle, 77 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_authenticodesigner_get($this->handle, 78 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_authenticodesigner_get($this->handle, 79 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_authenticodesigner_get($this->handle, 80 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_authenticodesigner_get($this->handle, 81 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 81, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_authenticodesigner_get($this->handle, 82 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 82, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_authenticodesigner_get($this->handle, 83 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 83, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_authenticodesigner_get($this->handle, 84 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 84, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_authenticodesigner_get($this->handle, 85 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 85, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  */
  public function getTrustedCertCount() {
    return secureblackbox_authenticodesigner_get($this->handle, 86 );
  }
 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTrustedCertCount($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTrustedCertBytes($trustedcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 87 , $trustedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTrustedCertHandle($trustedcertindex) {
    return secureblackbox_authenticodesigner_get($this->handle, 88 , $trustedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTrustedCertHandle($trustedcertindex, $value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 88, $value , $trustedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the complete log of the certificate validation routine.
  *
  * @access   public
  */
  public function getValidationLog() {
    return secureblackbox_authenticodesigner_get($this->handle, 89 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_authenticodesigner_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_authenticodesigner_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticodesigner_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Information about errors during Authenticode signing.
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
  * This event notifies the application about an underlying control flow event.
  *
  * @access   public
  * @param    array   Array of event parameters: eventid, eventparam    
  */
  public function fireNotification($param) {
    return $param;
  }

 /**
  * This event is fired when the class is about to start the signing process.
  *
  * @access   public
  * @param    array   Array of event parameters: specifiedchecksum, actualchecksum, issigned, cancel    
  */
  public function fireStart($param) {
    return $param;
  }

 /**
  * This event is fired upon receipt of the TLS server's certificate, allowing the user to control its acceptance.
  *
  * @access   public
  * @param    array   Array of event parameters: serverhostname, serverip, accept    
  */
  public function fireTLSCertValidate($param) {
    return $param;
  }


}

?>
