<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - Authenticator Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_Authenticator {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_authenticator_open(SECUREBLACKBOX_OEMKEY_950);
    secureblackbox_authenticator_register_callback($this->handle, 1, array($this, 'fireAuthAttemptResult'));
    secureblackbox_authenticator_register_callback($this->handle, 2, array($this, 'fireAuthAttemptStart'));
    secureblackbox_authenticator_register_callback($this->handle, 3, array($this, 'fireAuthStart'));
    secureblackbox_authenticator_register_callback($this->handle, 4, array($this, 'fireAuthVerify'));
    secureblackbox_authenticator_register_callback($this->handle, 5, array($this, 'fireCustomAuthStart'));
    secureblackbox_authenticator_register_callback($this->handle, 6, array($this, 'fireError'));
    secureblackbox_authenticator_register_callback($this->handle, 7, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_authenticator_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_authenticator_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_authenticator_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_authenticator_do_config($this->handle, $configurationstring);
		$err = secureblackbox_authenticator_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Call this method to process an authentication token and proceed to the next authentication step.
  *
  * @access   public
  * @param    string    state
  * @param    string    authtoken
  */
  public function doContinueAuth($state, $authtoken) {
    $ret = secureblackbox_authenticator_do_continueauth($this->handle, $state, $authtoken);
		$err = secureblackbox_authenticator_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Initiates an authentication process.
  *
  * @access   public
  * @param    string    userid
  */
  public function doStartAuth($userid) {
    $ret = secureblackbox_authenticator_do_startauth($this->handle, $userid);
		$err = secureblackbox_authenticator_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_authenticator_get($this->handle, 0);
  }
 /**
  * Contains the authentication log.
  *
  * @access   public
  */
  public function getAuthInfoAuthLog() {
    return secureblackbox_authenticator_get($this->handle, 1 );
  }


 /**
  * Contains the current authentication method.
  *
  * @access   public
  */
  public function getAuthInfoAuthMethod() {
    return secureblackbox_authenticator_get($this->handle, 2 );
  }


 /**
  * Contains the authentication method parameters.
  *
  * @access   public
  */
  public function getAuthInfoAuthMethodPars() {
    return secureblackbox_authenticator_get($this->handle, 3 );
  }


 /**
  * Contains a comma-separated list of completed authentication methods.
  *
  * @access   public
  */
  public function getAuthInfoCompletedMethods() {
    return secureblackbox_authenticator_get($this->handle, 4 );
  }


 /**
  * Contains an uninterpreted authentication message to be displayed to the authenticating user.
  *
  * @access   public
  */
  public function getAuthInfoLastAuthMessage() {
    return secureblackbox_authenticator_get($this->handle, 5 );
  }


 /**
  * Contains the result of the last authentication token validation.
  *
  * @access   public
  */
  public function getAuthInfoLastAuthResult() {
    return secureblackbox_authenticator_get($this->handle, 6 );
  }


 /**
  * Contains a comma-separated list of authentication methods yet to perform.
  *
  * @access   public
  */
  public function getAuthInfoRemainingMethods() {
    return secureblackbox_authenticator_get($this->handle, 7 );
  }


 /**
  * Contains a state of the overall authentication process.
  *
  * @access   public
  */
  public function getAuthInfoState() {
    return secureblackbox_authenticator_get($this->handle, 8 );
  }


 /**
  * Returns the ID of the user being authenticated, as passed to StartAuth .
  *
  * @access   public
  */
  public function getAuthInfoUserID() {
    return secureblackbox_authenticator_get($this->handle, 9 );
  }


 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  */
  public function getBlockedCertCount() {
    return secureblackbox_authenticator_get($this->handle, 10 );
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setBlockedCertCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getBlockedCertBytes($blockedcertindex) {
    return secureblackbox_authenticator_get($this->handle, 11 , $blockedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getBlockedCertHandle($blockedcertindex) {
    return secureblackbox_authenticator_get($this->handle, 12 , $blockedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setBlockedCertHandle($blockedcertindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 12, $value , $blockedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the Cert arrays.
  *
  * @access   public
  */
  public function getCertCount() {
    return secureblackbox_authenticator_get($this->handle, 13 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertBytes($certindex) {
    return secureblackbox_authenticator_get($this->handle, 14 , $certindex);
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getCertCA($certindex) {
    return secureblackbox_authenticator_get($this->handle, 15 , $certindex);
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getCertCAKeyID($certindex) {
    return secureblackbox_authenticator_get($this->handle, 16 , $certindex);
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getCertCRLDistributionPoints($certindex) {
    return secureblackbox_authenticator_get($this->handle, 17 , $certindex);
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getCertCurve($certindex) {
    return secureblackbox_authenticator_get($this->handle, 18 , $certindex);
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getCertFingerprint($certindex) {
    return secureblackbox_authenticator_get($this->handle, 19 , $certindex);
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getCertFriendlyName($certindex) {
    return secureblackbox_authenticator_get($this->handle, 20 , $certindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertHandle($certindex) {
    return secureblackbox_authenticator_get($this->handle, 21 , $certindex);
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getCertHashAlgorithm($certindex) {
    return secureblackbox_authenticator_get($this->handle, 22 , $certindex);
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCertIssuer($certindex) {
    return secureblackbox_authenticator_get($this->handle, 23 , $certindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getCertIssuerRDN($certindex) {
    return secureblackbox_authenticator_get($this->handle, 24 , $certindex);
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getCertKeyAlgorithm($certindex) {
    return secureblackbox_authenticator_get($this->handle, 25 , $certindex);
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getCertKeyBits($certindex) {
    return secureblackbox_authenticator_get($this->handle, 26 , $certindex);
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getCertKeyFingerprint($certindex) {
    return secureblackbox_authenticator_get($this->handle, 27 , $certindex);
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getCertKeyUsage($certindex) {
    return secureblackbox_authenticator_get($this->handle, 28 , $certindex);
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getCertKeyValid($certindex) {
    return secureblackbox_authenticator_get($this->handle, 29 , $certindex);
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getCertOCSPLocations($certindex) {
    return secureblackbox_authenticator_get($this->handle, 30 , $certindex);
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getCertPolicyIDs($certindex) {
    return secureblackbox_authenticator_get($this->handle, 31 , $certindex);
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getCertPublicKeyBytes($certindex) {
    return secureblackbox_authenticator_get($this->handle, 32 , $certindex);
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getCertSelfSigned($certindex) {
    return secureblackbox_authenticator_get($this->handle, 33 , $certindex);
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getCertSerialNumber($certindex) {
    return secureblackbox_authenticator_get($this->handle, 34 , $certindex);
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getCertSigAlgorithm($certindex) {
    return secureblackbox_authenticator_get($this->handle, 35 , $certindex);
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getCertSubject($certindex) {
    return secureblackbox_authenticator_get($this->handle, 36 , $certindex);
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getCertSubjectKeyID($certindex) {
    return secureblackbox_authenticator_get($this->handle, 37 , $certindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getCertSubjectRDN($certindex) {
    return secureblackbox_authenticator_get($this->handle, 38 , $certindex);
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getCertValidFrom($certindex) {
    return secureblackbox_authenticator_get($this->handle, 39 , $certindex);
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getCertValidTo($certindex) {
    return secureblackbox_authenticator_get($this->handle, 40 , $certindex);
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getChainValidationDetails() {
    return secureblackbox_authenticator_get($this->handle, 41 );
  }


 /**
  * The general outcome of a certificate chain validation routine. Use ChainValidationDetails to get information about the reasons that contributed to the validation result.
  *
  * @access   public
  */
  public function getChainValidationResult() {
    return secureblackbox_authenticator_get($this->handle, 42 );
  }


 /**
  * Contains the list of default authentication methods.
  *
  * @access   public
  */
  public function getDefaultAuthMethods() {
    return secureblackbox_authenticator_get($this->handle, 43 );
  }
 /**
  * Contains the list of default authentication methods.
  *
  * @access   public
  * @param    string   value
  */
  public function setDefaultAuthMethods($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 43, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_authenticator_get($this->handle, 44 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 44, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_authenticator_get($this->handle, 45 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 45, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_authenticator_get($this->handle, 46 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 46, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_authenticator_get($this->handle, 47 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_authenticator_get($this->handle, 48 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 48, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_authenticator_get($this->handle, 49 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 49, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_authenticator_get($this->handle, 50 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 50, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_authenticator_get($this->handle, 51 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 51, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_authenticator_get($this->handle, 52 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 52, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  */
  public function getIgnoreChainValidationErrors() {
    return secureblackbox_authenticator_get($this->handle, 53 );
  }
 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIgnoreChainValidationErrors($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 53, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_authenticator_get($this->handle, 54 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 54, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_authenticator_get($this->handle, 55 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_authenticator_get($this->handle, 56 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 56, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  */
  public function getKnownCRLCount() {
    return secureblackbox_authenticator_get($this->handle, 57 );
  }
 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCRLCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 57, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getKnownCRLBytes($knowncrlindex) {
    return secureblackbox_authenticator_get($this->handle, 58 , $knowncrlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCRLHandle($knowncrlindex) {
    return secureblackbox_authenticator_get($this->handle, 59 , $knowncrlindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCRLHandle($knowncrlindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 59, $value , $knowncrlindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  */
  public function getKnownOCSPCount() {
    return secureblackbox_authenticator_get($this->handle, 60 );
  }
 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownOCSPCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 60, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getKnownOCSPBytes($knownocspindex) {
    return secureblackbox_authenticator_get($this->handle, 61 , $knownocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownOCSPHandle($knownocspindex) {
    return secureblackbox_authenticator_get($this->handle, 62 , $knownocspindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownOCSPHandle($knownocspindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 62, $value , $knownocspindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  */
  public function getOfflineMode() {
    return secureblackbox_authenticator_get($this->handle, 63 );
  }
 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOfflineMode($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 63, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxyAddress() {
    return secureblackbox_authenticator_get($this->handle, 64 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyAddress($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 64, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxyAuthentication() {
    return secureblackbox_authenticator_get($this->handle, 65 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyAuthentication($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 65, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxyPassword() {
    return secureblackbox_authenticator_get($this->handle, 66 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyPassword($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 66, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxyPort() {
    return secureblackbox_authenticator_get($this->handle, 67 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyPort($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 67, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxyProxyType() {
    return secureblackbox_authenticator_get($this->handle, 68 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyProxyType($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 68, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxyRequestHeaders() {
    return secureblackbox_authenticator_get($this->handle, 69 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyRequestHeaders($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 69, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxyResponseBody() {
    return secureblackbox_authenticator_get($this->handle, 70 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseBody($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 70, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxyResponseHeaders() {
    return secureblackbox_authenticator_get($this->handle, 71 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseHeaders($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxyUseIPv6() {
    return secureblackbox_authenticator_get($this->handle, 72 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseIPv6($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 72, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxyUseProxy() {
    return secureblackbox_authenticator_get($this->handle, 73 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseProxy($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxyUsername() {
    return secureblackbox_authenticator_get($this->handle, 74 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyUsername($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getRevocationCheck() {
    return secureblackbox_authenticator_get($this->handle, 75 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setRevocationCheck($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_authenticator_get($this->handle, 76 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_authenticator_get($this->handle, 77 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningCertHandle($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_authenticator_get($this->handle, 78 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_authenticator_get($this->handle, 79 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_authenticator_get($this->handle, 80 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_authenticator_get($this->handle, 81 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 81, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_authenticator_get($this->handle, 82 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 82, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_authenticator_get($this->handle, 83 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 83, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_authenticator_get($this->handle, 84 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 84, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_authenticator_get($this->handle, 85 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 85, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_authenticator_get($this->handle, 86 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_authenticator_get($this->handle, 87 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 87, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_authenticator_get($this->handle, 88 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 88, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_authenticator_get($this->handle, 89 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 89, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_authenticator_get($this->handle, 90 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_authenticator_get($this->handle, 91 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 91, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_authenticator_get($this->handle, 92 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 92, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_authenticator_get($this->handle, 93 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 93, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_authenticator_get($this->handle, 94 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 94, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_authenticator_get($this->handle, 95 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 95, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_authenticator_get($this->handle, 96 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 96, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_authenticator_get($this->handle, 97 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 97, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_authenticator_get($this->handle, 98 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 98, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_authenticator_get($this->handle, 99 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 99, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_authenticator_get($this->handle, 100 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 100, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_authenticator_get($this->handle, 101 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 101, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_authenticator_get($this->handle, 102 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 102, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_authenticator_get($this->handle, 103 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 103, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  */
  public function getTrustedCertCount() {
    return secureblackbox_authenticator_get($this->handle, 104 );
  }
 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTrustedCertCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 104, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTrustedCertBytes($trustedcertindex) {
    return secureblackbox_authenticator_get($this->handle, 105 , $trustedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTrustedCertHandle($trustedcertindex) {
    return secureblackbox_authenticator_get($this->handle, 106 , $trustedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTrustedCertHandle($trustedcertindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 106, $value , $trustedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the User arrays.
  *
  * @access   public
  */
  public function getUserCount() {
    return secureblackbox_authenticator_get($this->handle, 107 );
  }
 /**
  * The number of records in the User arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserCount($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 107, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  */
  public function getUserAssociatedData($userindex) {
    return secureblackbox_authenticator_get($this->handle, 108 , $userindex);
  }
 /**
  * Contains the user's Associated Data when SSH AEAD (Authenticated Encryption with Associated Data) algorithm is used.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserAssociatedData($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 108, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  */
  public function getUserBasePath($userindex) {
    return secureblackbox_authenticator_get($this->handle, 109 , $userindex);
  }
 /**
  * Base path for this user in the server's file system.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserBasePath($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 109, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's certificate.
  *
  * @access   public
  */
  public function getUserCert($userindex) {
    return secureblackbox_authenticator_get($this->handle, 110 , $userindex);
  }
 /**
  * Contains the user's certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserCert($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 110, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  */
  public function getUserData($userindex) {
    return secureblackbox_authenticator_get($this->handle, 111 , $userindex);
  }
 /**
  * Contains uninterpreted user-defined data that should be associated with the user account, such as comments or custom settings.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserData($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 111, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getUserHandle($userindex) {
    return secureblackbox_authenticator_get($this->handle, 112 , $userindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setUserHandle($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 112, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  */
  public function getUserHashAlgorithm($userindex) {
    return secureblackbox_authenticator_get($this->handle, 113 , $userindex);
  }
 /**
  * Specifies the hash algorithm used to generate TOTP (Time-based One-Time Passwords) passwords for this user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserHashAlgorithm($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 113, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  */
  public function getUserIncomingSpeedLimit($userindex) {
    return secureblackbox_authenticator_get($this->handle, 114 , $userindex);
  }
 /**
  * Specifies the incoming speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserIncomingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 114, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm used to generate one-time passwords (OTP) for this user, either HOTP (Hash-based OTP) or TOTP (Time-based OTP).
  *
  * @access   public
  */
  public function getUserOtpAlgorithm($userindex) {
    return secureblackbox_authenticator_get($this->handle, 115 , $userindex);
  }
 /**
  * The algorithm used to generate one-time passwords (OTP) for this user, either HOTP (Hash-based OTP) or TOTP (Time-based OTP).
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOtpAlgorithm($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 115, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user's time interval (TOTP) or Counter (HOTP).
  *
  * @access   public
  */
  public function getUserOtpValue($userindex) {
    return secureblackbox_authenticator_get($this->handle, 116 , $userindex);
  }
 /**
  * The user's time interval (TOTP) or Counter (HOTP).
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOtpValue($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 116, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  */
  public function getUserOutgoingSpeedLimit($userindex) {
    return secureblackbox_authenticator_get($this->handle, 117 , $userindex);
  }
 /**
  * Specifies the outgoing speed limit for this user.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserOutgoingSpeedLimit($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 117, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The user's authentication password.
  *
  * @access   public
  */
  public function getUserPassword($userindex) {
    return secureblackbox_authenticator_get($this->handle, 118 , $userindex);
  }
 /**
  * The user's authentication password.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserPassword($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 118, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the length of the user's OTP password.
  *
  * @access   public
  */
  public function getUserPasswordLen($userindex) {
    return secureblackbox_authenticator_get($this->handle, 119 , $userindex);
  }
 /**
  * Specifies the length of the user's OTP password.
  *
  * @access   public
  * @param    int   value
  */
  public function setUserPasswordLen($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 119, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  */
  public function getUserSharedSecret($userindex) {
    return secureblackbox_authenticator_get($this->handle, 120 , $userindex);
  }
 /**
  * Contains the user's secret key, which is essentially a shared secret between the client and server.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserSharedSecret($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 120, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the user's SSH key.
  *
  * @access   public
  */
  public function getUserSSHKey($userindex) {
    return secureblackbox_authenticator_get($this->handle, 121 , $userindex);
  }
 /**
  * Contains the user's SSH key.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserSSHKey($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 121, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The registered name (login) of the user.
  *
  * @access   public
  */
  public function getUserUsername($userindex) {
    return secureblackbox_authenticator_get($this->handle, 122 , $userindex);
  }
 /**
  * The registered name (login) of the user.
  *
  * @access   public
  * @param    string   value
  */
  public function setUserUsername($userindex, $value) {
    $ret = secureblackbox_authenticator_set($this->handle, 122, $value , $userindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the complete log of the certificate validation routine.
  *
  * @access   public
  */
  public function getValidationLog() {
    return secureblackbox_authenticator_get($this->handle, 123 );
  }


 /**
  * The time point at which signature validity is to be established.
  *
  * @access   public
  */
  public function getValidationMoment() {
    return secureblackbox_authenticator_get($this->handle, 124 );
  }
 /**
  * The time point at which signature validity is to be established.
  *
  * @access   public
  * @param    string   value
  */
  public function setValidationMoment($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 124, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_authenticator_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_authenticator_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_authenticator_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Reports the outcome of an authentication attempt.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, authmethod, authres, remainingauthmethods    
  */
  public function fireAuthAttemptResult($param) {
    return $param;
  }

 /**
  * Signifies the start of an authentication attempt.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, authmethod, remainingauthmethods    
  */
  public function fireAuthAttemptStart($param) {
    return $param;
  }

 /**
  * Signifies the start of an authentication process.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, authmethods    
  */
  public function fireAuthStart($param) {
    return $param;
  }

 /**
  * Requests the application to validate an authentication token.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, authmethod, authtoken, authmethoddata, valid    
  */
  public function fireAuthVerify($param) {
    return $param;
  }

 /**
  * Reports the beginning of a custom authentication method.
  *
  * @access   public
  * @param    array   Array of event parameters: userid, authmethod, authmethodpars, authmethoddata    
  */
  public function fireCustomAuthStart($param) {
    return $param;
  }

 /**
  * Reports information about errors during authentication.
  *
  * @access   public
  * @param    array   Array of event parameters: errorcode, description    
  */
  public function fireError($param) {
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


}

?>
