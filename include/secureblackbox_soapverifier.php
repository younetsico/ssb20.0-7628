<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SOAPVerifier Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SOAPVerifier {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_soapverifier_open(SECUREBLACKBOX_OEMKEY_924);
    secureblackbox_soapverifier_register_callback($this->handle, 1, array($this, 'fireChainValidated'));
    secureblackbox_soapverifier_register_callback($this->handle, 2, array($this, 'fireError'));
    secureblackbox_soapverifier_register_callback($this->handle, 3, array($this, 'fireNotification'));
    secureblackbox_soapverifier_register_callback($this->handle, 4, array($this, 'fireReferenceValidated'));
    secureblackbox_soapverifier_register_callback($this->handle, 5, array($this, 'fireResolveReference'));
    secureblackbox_soapverifier_register_callback($this->handle, 6, array($this, 'fireRetrieveCertificate'));
    secureblackbox_soapverifier_register_callback($this->handle, 7, array($this, 'fireRetrieveCRL'));
    secureblackbox_soapverifier_register_callback($this->handle, 8, array($this, 'fireRetrieveOCSPResponse'));
    secureblackbox_soapverifier_register_callback($this->handle, 9, array($this, 'fireSignatureFound'));
    secureblackbox_soapverifier_register_callback($this->handle, 10, array($this, 'fireSignatureValidated'));
    secureblackbox_soapverifier_register_callback($this->handle, 11, array($this, 'fireStoreCertificate'));
    secureblackbox_soapverifier_register_callback($this->handle, 12, array($this, 'fireStoreCRL'));
    secureblackbox_soapverifier_register_callback($this->handle, 13, array($this, 'fireStoreOCSPResponse'));
    secureblackbox_soapverifier_register_callback($this->handle, 14, array($this, 'fireTimestampFound'));
    secureblackbox_soapverifier_register_callback($this->handle, 15, array($this, 'fireTimestampValidated'));
    secureblackbox_soapverifier_register_callback($this->handle, 16, array($this, 'fireTLSCertValidate'));
  }
  
  public function __destruct() {
    secureblackbox_soapverifier_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_soapverifier_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_soapverifier_get_last_error_code($this->handle);
  }

 /**
  * Use this method to add an timestamp.
  *
  * @access   public
  * @param    int    timestamptype
  * @param    string    timestampserver
  */
  public function doAddTimestamp($timestamptype, $timestampserver) {
    $ret = secureblackbox_soapverifier_do_addtimestamp($this->handle, $timestamptype, $timestampserver);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this method to add timestamp validation data to the signature.
  *
  * @access   public
  */
  public function doAddTimestampValidationData() {
    $ret = secureblackbox_soapverifier_do_addtimestampvalidationdata($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this method to add signature validation references to the signature.
  *
  * @access   public
  */
  public function doAddValidationDataRefs() {
    $ret = secureblackbox_soapverifier_do_addvalidationdatarefs($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this method to add signature validation values to the signature.
  *
  * @access   public
  */
  public function doAddValidationDataValues() {
    $ret = secureblackbox_soapverifier_do_addvalidationdatavalues($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
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
    $ret = secureblackbox_soapverifier_do_config($this->handle, $configurationstring);
		$err = secureblackbox_soapverifier_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies a digitally signed SOAP message.
  *
  * @access   public
  */
  public function doVerify() {
    $ret = secureblackbox_soapverifier_do_verify($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_soapverifier_get($this->handle, 0);
  }
 /**
  * The cumulative validity of all signatures.
  *
  * @access   public
  */
  public function getAllSignaturesValid() {
    return secureblackbox_soapverifier_get($this->handle, 1 );
  }


 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  */
  public function getBlockedCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 2 );
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setBlockedCertCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getBlockedCertBytes($blockedcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 3 , $blockedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getBlockedCertHandle($blockedcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 4 , $blockedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setBlockedCertHandle($blockedcertindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 4, $value , $blockedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The XML canonicalization method that was used for signing.
  *
  * @access   public
  */
  public function getCanonicalizationMethod() {
    return secureblackbox_soapverifier_get($this->handle, 5 );
  }


 /**
  * The number of records in the Cert arrays.
  *
  * @access   public
  */
  public function getCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 6 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertBytes($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 7 , $certindex);
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getCertCA($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 8 , $certindex);
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getCertCAKeyID($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 9 , $certindex);
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getCertCRLDistributionPoints($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 10 , $certindex);
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getCertCurve($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 11 , $certindex);
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getCertFingerprint($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 12 , $certindex);
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getCertFriendlyName($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 13 , $certindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertHandle($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 14 , $certindex);
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getCertHashAlgorithm($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 15 , $certindex);
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCertIssuer($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 16 , $certindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getCertIssuerRDN($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 17 , $certindex);
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getCertKeyAlgorithm($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 18 , $certindex);
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getCertKeyBits($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 19 , $certindex);
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getCertKeyFingerprint($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 20 , $certindex);
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getCertKeyUsage($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 21 , $certindex);
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getCertKeyValid($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 22 , $certindex);
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getCertOCSPLocations($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 23 , $certindex);
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getCertPolicyIDs($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 24 , $certindex);
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getCertPublicKeyBytes($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 25 , $certindex);
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getCertSelfSigned($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 26 , $certindex);
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getCertSerialNumber($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 27 , $certindex);
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getCertSigAlgorithm($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 28 , $certindex);
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getCertSubject($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 29 , $certindex);
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getCertSubjectKeyID($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 30 , $certindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getCertSubjectRDN($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 31 , $certindex);
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getCertValidFrom($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 32 , $certindex);
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getCertValidTo($certindex) {
    return secureblackbox_soapverifier_get($this->handle, 33 , $certindex);
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getChainValidationDetails() {
    return secureblackbox_soapverifier_get($this->handle, 34 );
  }


 /**
  * The general outcome of a certificate chain validation routine. Use ChainValidationDetails to get information about the reasons that contributed to the validation result.
  *
  * @access   public
  */
  public function getChainValidationResult() {
    return secureblackbox_soapverifier_get($this->handle, 35 );
  }


 /**
  * Returns a signature's claimed signing time.
  *
  * @access   public
  */
  public function getClaimedSigningTime() {
    return secureblackbox_soapverifier_get($this->handle, 36 );
  }


 /**
  * The number of records in the CRL arrays.
  *
  * @access   public
  */
  public function getCRLCount() {
    return secureblackbox_soapverifier_get($this->handle, 37 );
  }


 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getCRLBytes($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 38 , $crlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCRLHandle($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 39 , $crlindex);
  }


 /**
  * The common name of the CRL issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCRLIssuer($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 40 , $crlindex);
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the CRL issuer.
  *
  * @access   public
  */
  public function getCRLIssuerRDN($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 41 , $crlindex);
  }


 /**
  * The URL that the CRL was downloaded from.
  *
  * @access   public
  */
  public function getCRLLocation($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 42 , $crlindex);
  }


 /**
  * The planned time and date of the next version of this CRL to be published.
  *
  * @access   public
  */
  public function getCRLNextUpdate($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 43 , $crlindex);
  }


 /**
  * The date and time at which this version of the CRL was published.
  *
  * @access   public
  */
  public function getCRLThisUpdate($crlindex) {
    return secureblackbox_soapverifier_get($this->handle, 44 , $crlindex);
  }


 /**
  * Specifies XML encoding.
  *
  * @access   public
  */
  public function getEncoding() {
    return secureblackbox_soapverifier_get($this->handle, 45 );
  }
 /**
  * Specifies XML encoding.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncoding($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 45, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash algorithm used for signing.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 46 );
  }


 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  */
  public function getIgnoreChainValidationErrors() {
    return secureblackbox_soapverifier_get($this->handle, 47 );
  }
 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIgnoreChainValidationErrors($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  */
  public function getInputBytes() {
    return secureblackbox_soapverifier_get($this->handle, 48 );
  }
 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputBytes($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 48, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A path to the signed SOAP message.
  *
  * @access   public
  */
  public function getInputFile() {
    return secureblackbox_soapverifier_get($this->handle, 49 );
  }
 /**
  * A path to the signed SOAP message.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 49, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 50 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 50, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_soapverifier_get($this->handle, 51 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_soapverifier_get($this->handle, 52 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 52, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  */
  public function getKnownCRLCount() {
    return secureblackbox_soapverifier_get($this->handle, 53 );
  }
 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCRLCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 53, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getKnownCRLBytes($knowncrlindex) {
    return secureblackbox_soapverifier_get($this->handle, 54 , $knowncrlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCRLHandle($knowncrlindex) {
    return secureblackbox_soapverifier_get($this->handle, 55 , $knowncrlindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCRLHandle($knowncrlindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 55, $value , $knowncrlindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  */
  public function getKnownOCSPCount() {
    return secureblackbox_soapverifier_get($this->handle, 56 );
  }
 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownOCSPCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 56, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getKnownOCSPBytes($knownocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 57 , $knownocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownOCSPHandle($knownocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 58 , $knownocspindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownOCSPHandle($knownocspindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 58, $value , $knownocspindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the most recent archival time of an archived signature.
  *
  * @access   public
  */
  public function getLastArchivalTime() {
    return secureblackbox_soapverifier_get($this->handle, 59 );
  }


 /**
  * The number of records in the OCSP arrays.
  *
  * @access   public
  */
  public function getOCSPCount() {
    return secureblackbox_soapverifier_get($this->handle, 60 );
  }


 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getOCSPBytes($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 61 , $ocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getOCSPHandle($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 62 , $ocspindex);
  }


 /**
  * Indicates the issuer of this response (a CA or its authorized representative).
  *
  * @access   public
  */
  public function getOCSPIssuer($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 63 , $ocspindex);
  }


 /**
  * Indicates the RDN of the issuer of this response (a CA or its authorized representative).
  *
  * @access   public
  */
  public function getOCSPIssuerRDN($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 64 , $ocspindex);
  }


 /**
  * Location of the OCSP responder.
  *
  * @access   public
  */
  public function getOCSPLocation($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 65 , $ocspindex);
  }


 /**
  * Specifies the time when the response was produced, in UTC.
  *
  * @access   public
  */
  public function getOCSPProducedAt($ocspindex) {
    return secureblackbox_soapverifier_get($this->handle, 66 , $ocspindex);
  }


 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  */
  public function getOfflineMode() {
    return secureblackbox_soapverifier_get($this->handle, 67 );
  }
 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOfflineMode($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 67, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to read the output the class object has produced.
  *
  * @access   public
  */
  public function getOutputBytes() {
    return secureblackbox_soapverifier_get($this->handle, 68 );
  }


 /**
  * A file where the extracted SOAP message is to be saved.
  *
  * @access   public
  */
  public function getOutputFile() {
    return secureblackbox_soapverifier_get($this->handle, 69 );
  }
 /**
  * A file where the extracted SOAP message is to be saved.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 69, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  */
  public function getProfile() {
    return secureblackbox_soapverifier_get($this->handle, 70 );
  }
 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setProfile($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 70, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxyAddress() {
    return secureblackbox_soapverifier_get($this->handle, 71 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyAddress($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxyAuthentication() {
    return secureblackbox_soapverifier_get($this->handle, 72 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyAuthentication($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 72, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxyPassword() {
    return secureblackbox_soapverifier_get($this->handle, 73 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyPassword($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxyPort() {
    return secureblackbox_soapverifier_get($this->handle, 74 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyPort($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxyProxyType() {
    return secureblackbox_soapverifier_get($this->handle, 75 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyProxyType($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxyRequestHeaders() {
    return secureblackbox_soapverifier_get($this->handle, 76 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyRequestHeaders($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxyResponseBody() {
    return secureblackbox_soapverifier_get($this->handle, 77 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseBody($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxyResponseHeaders() {
    return secureblackbox_soapverifier_get($this->handle, 78 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseHeaders($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxyUseIPv6() {
    return secureblackbox_soapverifier_get($this->handle, 79 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseIPv6($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxyUseProxy() {
    return secureblackbox_soapverifier_get($this->handle, 80 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseProxy($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxyUsername() {
    return secureblackbox_soapverifier_get($this->handle, 81 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyUsername($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 81, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates a qualified electronic signature.
  *
  * @access   public
  */
  public function getQualified() {
    return secureblackbox_soapverifier_get($this->handle, 82 );
  }


 /**
  * The number of records in the Reference arrays.
  *
  * @access   public
  */
  public function getReferenceCount() {
    return secureblackbox_soapverifier_get($this->handle, 83 );
  }


 /**
  * Specifies whether the identifier (ID) attribute for a referenced (target) element should be auto-generated during signing.
  *
  * @access   public
  */
  public function getReferenceAutoGenerateElementId($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 84 , $referenceindex);
  }


 /**
  * Use this property to specify the canonicalization method for the transform of the reference.
  *
  * @access   public
  */
  public function getReferenceCanonicalizationMethod($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 85 , $referenceindex);
  }


 /**
  * Specifies a custom identifier (ID) attribute for a referenced (target) element that will be set on signing.
  *
  * @access   public
  */
  public function getReferenceCustomElementId($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 86 , $referenceindex);
  }


 /**
  * Use this property to get or set the value of the digest calculated  over the referenced data.
  *
  * @access   public
  */
  public function getReferenceDigestValue($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 87 , $referenceindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getReferenceHandle($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 88 , $referenceindex);
  }


 /**
  * Specifies the hash algorithm to be used.
  *
  * @access   public
  */
  public function getReferenceHashAlgorithm($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 89 , $referenceindex);
  }


 /**
  * Specifies whether the URI is set (even when it is empty).
  *
  * @access   public
  */
  public function getReferenceHasURI($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 90 , $referenceindex);
  }


 /**
  * A user-defined identifier (ID) attribute of this Reference element.
  *
  * @access   public
  */
  public function getReferenceID($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 91 , $referenceindex);
  }


 /**
  * Use this property to specify InclusiveNamespaces PrefixList for exclusive canonicalization transform of the reference.
  *
  * @access   public
  */
  public function getReferenceInclusiveNamespacesPrefixList($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 92 , $referenceindex);
  }


 /**
  * The Reference's type attribute as defined in XMLDSIG specification.
  *
  * @access   public
  */
  public function getReferenceReferenceType($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 93 , $referenceindex);
  }


 /**
  * Contains the referenced external data when the digest value is not explicitly specified.
  *
  * @access   public
  */
  public function getReferenceTargetData($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 94 , $referenceindex);
  }


 /**
  * This property specifies the referenced XML element.
  *
  * @access   public
  */
  public function getReferenceTargetXMLElement($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 95 , $referenceindex);
  }


 /**
  * Use this property to get or set the URL which references the data.
  *
  * @access   public
  */
  public function getReferenceURI($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 96 , $referenceindex);
  }


 /**
  * Specifies whether Base64 transform is included in transform chain.
  *
  * @access   public
  */
  public function getReferenceUseBase64Transform($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 97 , $referenceindex);
  }


 /**
  * Specifies whether enveloped signature transform is included in transform chain.
  *
  * @access   public
  */
  public function getReferenceUseEnvelopedSignatureTransform($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 98 , $referenceindex);
  }


 /**
  * Specifies whether XPath Filter 2.
  *
  * @access   public
  */
  public function getReferenceUseXPathFilter2Transform($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 99 , $referenceindex);
  }


 /**
  * Specifies whether XPath transform is included in transform chain.
  *
  * @access   public
  */
  public function getReferenceUseXPathTransform($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 100 , $referenceindex);
  }


 /**
  * Use this property to specify XPath expression for XPath transform of the reference.
  *
  * @access   public
  */
  public function getReferenceXPathExpression($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 101 , $referenceindex);
  }


 /**
  * Use this property to specify XPointer expression(s) for XPath Filter 2.
  *
  * @access   public
  */
  public function getReferenceXPathFilter2Expressions($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 102 , $referenceindex);
  }


 /**
  * Use this property to specify XPointer filter(s) for XPath Filter 2.
  *
  * @access   public
  */
  public function getReferenceXPathFilter2Filters($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 103 , $referenceindex);
  }


 /**
  * Use this property to specify a prefix list for XPath Filter 2.
  *
  * @access   public
  */
  public function getReferenceXPathFilter2PrefixList($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 104 , $referenceindex);
  }


 /**
  * Use this property to specify a prefix list for XPath transform of the reference.
  *
  * @access   public
  */
  public function getReferenceXPathPrefixList($referenceindex) {
    return secureblackbox_soapverifier_get($this->handle, 105 , $referenceindex);
  }


 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getRevocationCheck() {
    return secureblackbox_soapverifier_get($this->handle, 106 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setRevocationCheck($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 106, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The index of the signature to update.
  *
  * @access   public
  */
  public function getSignatureIndex() {
    return secureblackbox_soapverifier_get($this->handle, 107 );
  }
 /**
  * The index of the signature to update.
  *
  * @access   public
  * @param    int   value
  */
  public function setSignatureIndex($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 107, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signature type that was used to sign the SOAP message.
  *
  * @access   public
  */
  public function getSignatureType() {
    return secureblackbox_soapverifier_get($this->handle, 108 );
  }


 /**
  * Contains the signature validation result.
  *
  * @access   public
  */
  public function getSignatureValidationResult() {
    return secureblackbox_soapverifier_get($this->handle, 109 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_soapverifier_get($this->handle, 110 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getSigningCertCA() {
    return secureblackbox_soapverifier_get($this->handle, 111 );
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertCAKeyID() {
    return secureblackbox_soapverifier_get($this->handle, 112 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getSigningCertCRLDistributionPoints() {
    return secureblackbox_soapverifier_get($this->handle, 113 );
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getSigningCertCurve() {
    return secureblackbox_soapverifier_get($this->handle, 114 );
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getSigningCertFingerprint() {
    return secureblackbox_soapverifier_get($this->handle, 115 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getSigningCertFriendlyName() {
    return secureblackbox_soapverifier_get($this->handle, 116 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_soapverifier_get($this->handle, 117 );
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getSigningCertHashAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 118 );
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getSigningCertIssuer() {
    return secureblackbox_soapverifier_get($this->handle, 119 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getSigningCertIssuerRDN() {
    return secureblackbox_soapverifier_get($this->handle, 120 );
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 121 );
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getSigningCertKeyBits() {
    return secureblackbox_soapverifier_get($this->handle, 122 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyFingerprint() {
    return secureblackbox_soapverifier_get($this->handle, 123 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getSigningCertKeyUsage() {
    return secureblackbox_soapverifier_get($this->handle, 124 );
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getSigningCertKeyValid() {
    return secureblackbox_soapverifier_get($this->handle, 125 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getSigningCertOCSPLocations() {
    return secureblackbox_soapverifier_get($this->handle, 126 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getSigningCertPolicyIDs() {
    return secureblackbox_soapverifier_get($this->handle, 127 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getSigningCertPublicKeyBytes() {
    return secureblackbox_soapverifier_get($this->handle, 128 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getSigningCertSelfSigned() {
    return secureblackbox_soapverifier_get($this->handle, 129 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getSigningCertSerialNumber() {
    return secureblackbox_soapverifier_get($this->handle, 130 );
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getSigningCertSigAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 131 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getSigningCertSubject() {
    return secureblackbox_soapverifier_get($this->handle, 132 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertSubjectKeyID() {
    return secureblackbox_soapverifier_get($this->handle, 133 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getSigningCertSubjectRDN() {
    return secureblackbox_soapverifier_get($this->handle, 134 );
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidFrom() {
    return secureblackbox_soapverifier_get($this->handle, 135 );
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidTo() {
    return secureblackbox_soapverifier_get($this->handle, 136 );
  }


 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_soapverifier_get($this->handle, 137 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 137, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_soapverifier_get($this->handle, 138 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 138, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_soapverifier_get($this->handle, 139 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 139, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_soapverifier_get($this->handle, 140 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 140, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_soapverifier_get($this->handle, 141 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 141, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_soapverifier_get($this->handle, 142 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 142, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_soapverifier_get($this->handle, 143 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 143, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_soapverifier_get($this->handle, 144 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 144, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_soapverifier_get($this->handle, 145 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 145, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_soapverifier_get($this->handle, 146 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 146, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_soapverifier_get($this->handle, 147 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 147, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * This property indicates the accuracy of the included time mark, in microseconds.
  *
  * @access   public
  */
  public function getTimestampAccuracy() {
    return secureblackbox_soapverifier_get($this->handle, 148 );
  }


 /**
  * Returns raw timestamp data in DER format.
  *
  * @access   public
  */
  public function getTimestampBytes() {
    return secureblackbox_soapverifier_get($this->handle, 149 );
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getTimestampChainValidationDetails() {
    return secureblackbox_soapverifier_get($this->handle, 150 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getTimestampChainValidationResult() {
    return secureblackbox_soapverifier_get($this->handle, 151 );
  }


 /**
  * Returns the timestamp's hash algorithm SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getTimestampHashAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 152 );
  }


 /**
  * Returns the timestamp's serial number.
  *
  * @access   public
  */
  public function getTimestampSerialNumber() {
    return secureblackbox_soapverifier_get($this->handle, 153 );
  }


 /**
  * The time point incorporated into the timestamp.
  *
  * @access   public
  */
  public function getTimestampTime() {
    return secureblackbox_soapverifier_get($this->handle, 154 );
  }


 /**
  * Returns the timestamp type.
  *
  * @access   public
  */
  public function getTimestampTimestampType() {
    return secureblackbox_soapverifier_get($this->handle, 155 );
  }


 /**
  * This value uniquely identifies the Timestamp Authority (TSA).
  *
  * @access   public
  */
  public function getTimestampTSAName() {
    return secureblackbox_soapverifier_get($this->handle, 156 );
  }


 /**
  * Contains the TSA certificate chain validation log.
  *
  * @access   public
  */
  public function getTimestampValidationLog() {
    return secureblackbox_soapverifier_get($this->handle, 157 );
  }


 /**
  * Contains timestamp validation outcome.
  *
  * @access   public
  */
  public function getTimestampValidationResult() {
    return secureblackbox_soapverifier_get($this->handle, 158 );
  }


 /**
  * Indicates whether or not the signature is timestamped.
  *
  * @access   public
  */
  public function getTimestamped() {
    return secureblackbox_soapverifier_get($this->handle, 159 );
  }


 /**
  * The number of records in the TLSClientCert arrays.
  *
  * @access   public
  */
  public function getTLSClientCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 160 );
  }
 /**
  * The number of records in the TLSClientCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSClientCertCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 160, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTLSClientCertBytes($tlsclientcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 161 , $tlsclientcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTLSClientCertHandle($tlsclientcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 162 , $tlsclientcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTLSClientCertHandle($tlsclientcertindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 162, $value , $tlsclientcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TLSServerCert arrays.
  *
  * @access   public
  */
  public function getTLSServerCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 163 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTLSServerCertBytes($tlsservercertindex) {
    return secureblackbox_soapverifier_get($this->handle, 164 , $tlsservercertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTLSServerCertHandle($tlsservercertindex) {
    return secureblackbox_soapverifier_get($this->handle, 165 , $tlsservercertindex);
  }


 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_soapverifier_get($this->handle, 166 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 166, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_soapverifier_get($this->handle, 167 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 167, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_soapverifier_get($this->handle, 168 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 168, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_soapverifier_get($this->handle, 169 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 169, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_soapverifier_get($this->handle, 170 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 170, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_soapverifier_get($this->handle, 171 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 171, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_soapverifier_get($this->handle, 172 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 172, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_soapverifier_get($this->handle, 173 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 173, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_soapverifier_get($this->handle, 174 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 174, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_soapverifier_get($this->handle, 175 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 175, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_soapverifier_get($this->handle, 176 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 176, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_soapverifier_get($this->handle, 177 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 177, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_soapverifier_get($this->handle, 178 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 178, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_soapverifier_get($this->handle, 179 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 179, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_soapverifier_get($this->handle, 180 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 180, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  */
  public function getTrustedCertCount() {
    return secureblackbox_soapverifier_get($this->handle, 181 );
  }
 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTrustedCertCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 181, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTrustedCertBytes($trustedcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 182 , $trustedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTrustedCertHandle($trustedcertindex) {
    return secureblackbox_soapverifier_get($this->handle, 183 , $trustedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTrustedCertHandle($trustedcertindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 183, $value , $trustedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTSACertBytes() {
    return secureblackbox_soapverifier_get($this->handle, 184 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getTSACertCA() {
    return secureblackbox_soapverifier_get($this->handle, 185 );
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getTSACertCAKeyID() {
    return secureblackbox_soapverifier_get($this->handle, 186 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getTSACertCRLDistributionPoints() {
    return secureblackbox_soapverifier_get($this->handle, 187 );
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getTSACertCurve() {
    return secureblackbox_soapverifier_get($this->handle, 188 );
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getTSACertFingerprint() {
    return secureblackbox_soapverifier_get($this->handle, 189 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getTSACertFriendlyName() {
    return secureblackbox_soapverifier_get($this->handle, 190 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTSACertHandle() {
    return secureblackbox_soapverifier_get($this->handle, 191 );
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getTSACertHashAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 192 );
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getTSACertIssuer() {
    return secureblackbox_soapverifier_get($this->handle, 193 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getTSACertIssuerRDN() {
    return secureblackbox_soapverifier_get($this->handle, 194 );
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getTSACertKeyAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 195 );
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getTSACertKeyBits() {
    return secureblackbox_soapverifier_get($this->handle, 196 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getTSACertKeyFingerprint() {
    return secureblackbox_soapverifier_get($this->handle, 197 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getTSACertKeyUsage() {
    return secureblackbox_soapverifier_get($this->handle, 198 );
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getTSACertKeyValid() {
    return secureblackbox_soapverifier_get($this->handle, 199 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getTSACertOCSPLocations() {
    return secureblackbox_soapverifier_get($this->handle, 200 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getTSACertPolicyIDs() {
    return secureblackbox_soapverifier_get($this->handle, 201 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getTSACertPublicKeyBytes() {
    return secureblackbox_soapverifier_get($this->handle, 202 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getTSACertSelfSigned() {
    return secureblackbox_soapverifier_get($this->handle, 203 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getTSACertSerialNumber() {
    return secureblackbox_soapverifier_get($this->handle, 204 );
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getTSACertSigAlgorithm() {
    return secureblackbox_soapverifier_get($this->handle, 205 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getTSACertSubject() {
    return secureblackbox_soapverifier_get($this->handle, 206 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getTSACertSubjectKeyID() {
    return secureblackbox_soapverifier_get($this->handle, 207 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getTSACertSubjectRDN() {
    return secureblackbox_soapverifier_get($this->handle, 208 );
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getTSACertValidFrom() {
    return secureblackbox_soapverifier_get($this->handle, 209 );
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getTSACertValidTo() {
    return secureblackbox_soapverifier_get($this->handle, 210 );
  }


 /**
  * Contains the certified signing time.
  *
  * @access   public
  */
  public function getValidatedSigningTime() {
    return secureblackbox_soapverifier_get($this->handle, 211 );
  }


 /**
  * Contains the complete log of the certificate validation routine.
  *
  * @access   public
  */
  public function getValidationLog() {
    return secureblackbox_soapverifier_get($this->handle, 212 );
  }


 /**
  * The time point at which signature validity is to be established.
  *
  * @access   public
  */
  public function getValidationMoment() {
    return secureblackbox_soapverifier_get($this->handle, 213 );
  }
 /**
  * The time point at which signature validity is to be established.
  *
  * @access   public
  * @param    string   value
  */
  public function setValidationMoment($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 213, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the document contains an advanced signature (XAdES).
  *
  * @access   public
  */
  public function getXAdESEnabled() {
    return secureblackbox_soapverifier_get($this->handle, 214 );
  }


 /**
  * Specifies which form of XAdES has been used.
  *
  * @access   public
  */
  public function getXAdESForm() {
    return secureblackbox_soapverifier_get($this->handle, 215 );
  }


 /**
  * Specifies XAdES version.
  *
  * @access   public
  */
  public function getXAdESVersion() {
    return secureblackbox_soapverifier_get($this->handle, 216 );
  }
 /**
  * Specifies XAdES version.
  *
  * @access   public
  * @param    int   value
  */
  public function setXAdESVersion($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 216, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the Namespace arrays.
  *
  * @access   public
  */
  public function getNamespaceCount() {
    return secureblackbox_soapverifier_get($this->handle, 217 );
  }
 /**
  * The number of records in the Namespace arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setNamespaceCount($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 217, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A user-defined prefix value of a namespace.
  *
  * @access   public
  */
  public function getNamespacePrefix($namespaceindex) {
    return secureblackbox_soapverifier_get($this->handle, 218 , $namespaceindex);
  }
 /**
  * A user-defined prefix value of a namespace.
  *
  * @access   public
  * @param    string   value
  */
  public function setNamespacePrefix($namespaceindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 218, $value , $namespaceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A user-defined URI value of a namespace.
  *
  * @access   public
  */
  public function getNamespaceURI($namespaceindex) {
    return secureblackbox_soapverifier_get($this->handle, 219 , $namespaceindex);
  }
 /**
  * A user-defined URI value of a namespace.
  *
  * @access   public
  * @param    string   value
  */
  public function setNamespaceURI($namespaceindex, $value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 219, $value , $namespaceindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_soapverifier_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_soapverifier_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_soapverifier_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Reports the end of the validation process.
  *
  * @access   public
  * @param    array   Array of event parameters: subjectrdn, validationresult, validationdetails    
  */
  public function fireChainValidated($param) {
    return $param;
  }

 /**
  * Information about errors during signature verification.
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

 /**
  * Marks the end of a reference validation.
  *
  * @access   public
  * @param    array   Array of event parameters: id, uri, reftype, referenceindex, digestvalid    
  */
  public function fireReferenceValidated($param) {
    return $param;
  }

 /**
  * Asks the application to resolve a reference.
  *
  * @access   public
  * @param    array   Array of event parameters: uri, referenceindex    
  */
  public function fireResolveReference($param) {
    return $param;
  }

 /**
  * This event is fired when a certificate should be retrieved.
  *
  * @access   public
  * @param    array   Array of event parameters: uri    
  */
  public function fireRetrieveCertificate($param) {
    return $param;
  }

 /**
  * This event is fired when a CRL should be retrieved.
  *
  * @access   public
  * @param    array   Array of event parameters: uri    
  */
  public function fireRetrieveCRL($param) {
    return $param;
  }

 /**
  * This event is fired when a OCSP Response should be retrieved.
  *
  * @access   public
  * @param    array   Array of event parameters: uri    
  */
  public function fireRetrieveOCSPResponse($param) {
    return $param;
  }

 /**
  * Signifies the start of signature validation.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, certfound, validatesignature, validatechain    
  */
  public function fireSignatureFound($param) {
    return $param;
  }

 /**
  * Reports the signature validation result.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, validationresult    
  */
  public function fireSignatureValidated($param) {
    return $param;
  }

 /**
  * This event is fired when a certificate should be stored along with a signature.
  *
  * @access   public
  * @param    array   Array of event parameters: cert, uri    
  */
  public function fireStoreCertificate($param) {
    return $param;
  }

 /**
  * This event is fired when a CRL should be stored along with a signature.
  *
  * @access   public
  * @param    array   Array of event parameters: crl, uri    
  */
  public function fireStoreCRL($param) {
    return $param;
  }

 /**
  * This event is fired when a OCSP Response should be stored along with a signature.
  *
  * @access   public
  * @param    array   Array of event parameters: ocspresponse, uri    
  */
  public function fireStoreOCSPResponse($param) {
    return $param;
  }

 /**
  * Signifies the start of a timestamp validation routine.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, certfound, validatetimestamp, validatechain    
  */
  public function fireTimestampFound($param) {
    return $param;
  }

 /**
  * Reports the completion of the timestamp validation routine.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, time, validationresult, chainvalidationresult, chainvalidationdetails    
  */
  public function fireTimestampValidated($param) {
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
