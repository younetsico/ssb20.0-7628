<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - CryptoKeyManager Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_CryptoKeyManager {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_cryptokeymanager_open(SECUREBLACKBOX_OEMKEY_401);
    secureblackbox_cryptokeymanager_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_cryptokeymanager_register_callback($this->handle, 2, array($this, 'fireNotification'));
    secureblackbox_cryptokeymanager_register_callback($this->handle, 3, array($this, 'firePasswordNeeded'));
  }
  
  public function __destruct() {
    secureblackbox_cryptokeymanager_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_cryptokeymanager_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_cryptokeymanager_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_cryptokeymanager_do_config($this->handle, $configurationstring);
		$err = secureblackbox_cryptokeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a strong cryptographic key from a password.
  *
  * @access   public
  * @param    int    keybits
  * @param    string    password
  * @param    string    salt
  */
  public function doDeriveKey($keybits, $password, $salt) {
    $ret = secureblackbox_cryptokeymanager_do_derivekey($this->handle, $keybits, $password, $salt);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the key to a byte array.
  *
  * @access   public
  * @param    int    format
  * @param    int    keytype
  */
  public function doExportBytes($format, $keytype) {
    $ret = secureblackbox_cryptokeymanager_do_exportbytes($this->handle, $format, $keytype);
		$err = secureblackbox_cryptokeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the key to a certificate.
  *
  * @access   public
  */
  public function doExportToCert() {
    $ret = secureblackbox_cryptokeymanager_do_exporttocert($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the key to a file.
  *
  * @access   public
  * @param    string    filename
  * @param    int    format
  * @param    int    keytype
  */
  public function doExportToFile($filename, $format, $keytype) {
    $ret = secureblackbox_cryptokeymanager_do_exporttofile($this->handle, $filename, $format, $keytype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a new crypto key.
  *
  * @access   public
  * @param    string    keyalgorithm
  * @param    string    scheme
  * @param    string    schemeparams
  * @param    int    keybits
  */
  public function doGenerate($keyalgorithm, $scheme, $schemeparams, $keybits) {
    $ret = secureblackbox_cryptokeymanager_do_generate($this->handle, $keyalgorithm, $scheme, $schemeparams, $keybits);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns an algorithm-specific key parameter.
  *
  * @access   public
  * @param    string    name
  */
  public function doGetKeyParam($name) {
    $ret = secureblackbox_cryptokeymanager_do_getkeyparam($this->handle, $name);
		$err = secureblackbox_cryptokeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns an algorithm-specific key parameter to a string.
  *
  * @access   public
  * @param    string    name
  */
  public function doGetKeyParamStr($name) {
    $ret = secureblackbox_cryptokeymanager_do_getkeyparamstr($this->handle, $name);
		$err = secureblackbox_cryptokeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads a key from a byte array.
  *
  * @access   public
  * @param    string    value
  * @param    int    format
  * @param    string    keyalgorithm
  * @param    string    scheme
  * @param    string    schemeparams
  * @param    int    keytype
  */
  public function doImportBytes($value, $format, $keyalgorithm, $scheme, $schemeparams, $keytype) {
    $ret = secureblackbox_cryptokeymanager_do_importbytes($this->handle, $value, $format, $keyalgorithm, $scheme, $schemeparams, $keytype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads a key from a certificate.
  *
  * @access   public
  */
  public function doImportFromCert() {
    $ret = secureblackbox_cryptokeymanager_do_importfromcert($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads a key from a file.
  *
  * @access   public
  * @param    string    filename
  * @param    int    format
  * @param    string    keyalgorithm
  * @param    string    scheme
  * @param    string    schemeparams
  * @param    int    keytype
  */
  public function doImportFromFile($filename, $format, $keyalgorithm, $scheme, $schemeparams, $keytype) {
    $ret = secureblackbox_cryptokeymanager_do_importfromfile($this->handle, $filename, $format, $keyalgorithm, $scheme, $schemeparams, $keytype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets an algorithm-specific key parameter.
  *
  * @access   public
  * @param    string    name
  * @param    string    value
  */
  public function doSetKeyParam($name, $value) {
    $ret = secureblackbox_cryptokeymanager_do_setkeyparam($this->handle, $name, $value);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets an algorithm-specific key parameter.
  *
  * @access   public
  * @param    string    name
  * @param    string    valuestr
  */
  public function doSetKeyParamStr($name, $valuestr) {
    $ret = secureblackbox_cryptokeymanager_do_setkeyparamstr($this->handle, $name, $valuestr);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_cryptokeymanager_get($this->handle, 0);
  }
 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertBytes() {
    return secureblackbox_cryptokeymanager_get($this->handle, 1 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getCertCA() {
    return secureblackbox_cryptokeymanager_get($this->handle, 2 );
  }
 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  * @param    boolean   value
  */
  public function setCertCA($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getCertCAKeyID() {
    return secureblackbox_cryptokeymanager_get($this->handle, 3 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getCertCRLDistributionPoints() {
    return secureblackbox_cryptokeymanager_get($this->handle, 4 );
  }
 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertCRLDistributionPoints($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getCertCurve() {
    return secureblackbox_cryptokeymanager_get($this->handle, 5 );
  }
 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertCurve($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getCertFingerprint() {
    return secureblackbox_cryptokeymanager_get($this->handle, 6 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getCertFriendlyName() {
    return secureblackbox_cryptokeymanager_get($this->handle, 7 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertHandle() {
    return secureblackbox_cryptokeymanager_get($this->handle, 8 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setCertHandle($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getCertHashAlgorithm() {
    return secureblackbox_cryptokeymanager_get($this->handle, 9 );
  }
 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  * @param    string   value
  */
  public function setCertHashAlgorithm($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCertIssuer() {
    return secureblackbox_cryptokeymanager_get($this->handle, 10 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getCertIssuerRDN() {
    return secureblackbox_cryptokeymanager_get($this->handle, 11 );
  }
 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertIssuerRDN($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getCertKeyAlgorithm() {
    return secureblackbox_cryptokeymanager_get($this->handle, 12 );
  }
 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertKeyAlgorithm($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getCertKeyBits() {
    return secureblackbox_cryptokeymanager_get($this->handle, 13 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getCertKeyFingerprint() {
    return secureblackbox_cryptokeymanager_get($this->handle, 14 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getCertKeyUsage() {
    return secureblackbox_cryptokeymanager_get($this->handle, 15 );
  }
 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertKeyUsage($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getCertKeyValid() {
    return secureblackbox_cryptokeymanager_get($this->handle, 16 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getCertOCSPLocations() {
    return secureblackbox_cryptokeymanager_get($this->handle, 17 );
  }
 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertOCSPLocations($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the origin of this certificate.
  *
  * @access   public
  */
  public function getCertOrigin() {
    return secureblackbox_cryptokeymanager_get($this->handle, 18 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getCertPolicyIDs() {
    return secureblackbox_cryptokeymanager_get($this->handle, 19 );
  }
 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertPolicyIDs($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the certificate's private key.
  *
  * @access   public
  */
  public function getCertPrivateKeyBytes() {
    return secureblackbox_cryptokeymanager_get($this->handle, 20 );
  }


 /**
  * Indicates whether the certificate has an associated private key.
  *
  * @access   public
  */
  public function getCertPrivateKeyExists() {
    return secureblackbox_cryptokeymanager_get($this->handle, 21 );
  }


 /**
  * Indicates whether the private key is extractable.
  *
  * @access   public
  */
  public function getCertPrivateKeyExtractable() {
    return secureblackbox_cryptokeymanager_get($this->handle, 22 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getCertPublicKeyBytes() {
    return secureblackbox_cryptokeymanager_get($this->handle, 23 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getCertSelfSigned() {
    return secureblackbox_cryptokeymanager_get($this->handle, 24 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getCertSerialNumber() {
    return secureblackbox_cryptokeymanager_get($this->handle, 25 );
  }
 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSerialNumber($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getCertSigAlgorithm() {
    return secureblackbox_cryptokeymanager_get($this->handle, 26 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getCertSubject() {
    return secureblackbox_cryptokeymanager_get($this->handle, 27 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getCertSubjectKeyID() {
    return secureblackbox_cryptokeymanager_get($this->handle, 28 );
  }
 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubjectKeyID($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getCertSubjectRDN() {
    return secureblackbox_cryptokeymanager_get($this->handle, 29 );
  }
 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubjectRDN($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getCertValidFrom() {
    return secureblackbox_cryptokeymanager_get($this->handle, 30 );
  }
 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertValidFrom($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getCertValidTo() {
    return secureblackbox_cryptokeymanager_get($this->handle, 31 );
  }
 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertValidTo($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 31, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getKeyAlgorithm() {
    return secureblackbox_cryptokeymanager_get($this->handle, 32 );
  }
 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyAlgorithm($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getKeyBits() {
    return secureblackbox_cryptokeymanager_get($this->handle, 33 );
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getKeyExportable() {
    return secureblackbox_cryptokeymanager_get($this->handle, 34 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_cryptokeymanager_get($this->handle, 35 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getKeyID() {
    return secureblackbox_cryptokeymanager_get($this->handle, 36 );
  }
 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyID($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getKeyIV() {
    return secureblackbox_cryptokeymanager_get($this->handle, 37 );
  }
 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyIV($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getKeyKey() {
    return secureblackbox_cryptokeymanager_get($this->handle, 38 );
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getKeyNonce() {
    return secureblackbox_cryptokeymanager_get($this->handle, 39 );
  }
 /**
  * A nonce value associated with a key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyNonce($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 39, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPrivate() {
    return secureblackbox_cryptokeymanager_get($this->handle, 40 );
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPublic() {
    return secureblackbox_cryptokeymanager_get($this->handle, 41 );
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getKeySubject() {
    return secureblackbox_cryptokeymanager_get($this->handle, 42 );
  }
 /**
  * Returns the key subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySubject($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 42, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getKeySymmetric() {
    return secureblackbox_cryptokeymanager_get($this->handle, 43 );
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getKeyValid() {
    return secureblackbox_cryptokeymanager_get($this->handle, 44 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_cryptokeymanager_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_cryptokeymanager_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeymanager_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Informs about an error during an operation.
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
  * This event is fired when a decryption password is needed.
  *
  * @access   public
  * @param    array   Array of event parameters: neededfor, password, cancel    
  */
  public function firePasswordNeeded($param) {
    return $param;
  }


}

?>
