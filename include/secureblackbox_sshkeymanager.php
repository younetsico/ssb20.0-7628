<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SSHKeyManager Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SSHKeyManager {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_sshkeymanager_open(SECUREBLACKBOX_OEMKEY_603);
    secureblackbox_sshkeymanager_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_sshkeymanager_register_callback($this->handle, 2, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_sshkeymanager_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_sshkeymanager_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_sshkeymanager_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_sshkeymanager_do_config($this->handle, $configurationstring);
		$err = secureblackbox_sshkeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Writes the key to a memory buffer.
  *
  * @access   public
  * @param    int    keytype
  * @param    string    password
  */
  public function doExportBytes($keytype, $password) {
    $ret = secureblackbox_sshkeymanager_do_exportbytes($this->handle, $keytype, $password);
		$err = secureblackbox_sshkeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the key to a certificate.
  *
  * @access   public
  */
  public function doExportToCert() {
    $ret = secureblackbox_sshkeymanager_do_exporttocert($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Exports the key to a crypto key object.
  *
  * @access   public
  */
  public function doExportToCryptoKey() {
    $ret = secureblackbox_sshkeymanager_do_exporttocryptokey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Writes key to file.
  *
  * @access   public
  * @param    int    keytype
  * @param    string    path
  * @param    string    password
  */
  public function doExportToFile($keytype, $path, $password) {
    $ret = secureblackbox_sshkeymanager_do_exporttofile($this->handle, $keytype, $path, $password);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a new SSH key.
  *
  * @access   public
  * @param    string    keyalgorithm
  * @param    string    scheme
  * @param    string    schemeparams
  * @param    int    keybits
  */
  public function doGenerate($keyalgorithm, $scheme, $schemeparams, $keybits) {
    $ret = secureblackbox_sshkeymanager_do_generate($this->handle, $keyalgorithm, $scheme, $schemeparams, $keybits);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
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
    $ret = secureblackbox_sshkeymanager_do_getkeyparam($this->handle, $name);
		$err = secureblackbox_sshkeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
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
    $ret = secureblackbox_sshkeymanager_do_getkeyparamstr($this->handle, $name);
		$err = secureblackbox_sshkeymanager_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads key from buffer.
  *
  * @access   public
  * @param    string    bytes
  * @param    string    password
  */
  public function doImportBytes($bytes, $password) {
    $ret = secureblackbox_sshkeymanager_do_importbytes($this->handle, $bytes, $password);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads a key from a certificate.
  *
  * @access   public
  */
  public function doImportFromCert() {
    $ret = secureblackbox_sshkeymanager_do_importfromcert($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Imports a key from a crypto key.
  *
  * @access   public
  */
  public function doImportFromCryptoKey() {
    $ret = secureblackbox_sshkeymanager_do_importfromcryptokey($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads key from file.
  *
  * @access   public
  * @param    string    path
  * @param    string    password
  */
  public function doImportFromFile($path, $password) {
    $ret = secureblackbox_sshkeymanager_do_importfromfile($this->handle, $path, $password);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
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
    $ret = secureblackbox_sshkeymanager_do_setkeyparam($this->handle, $name, $value);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
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
    $ret = secureblackbox_sshkeymanager_do_setkeyparamstr($this->handle, $name, $valuestr);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_sshkeymanager_get($this->handle, 0);
  }
 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertBytes() {
    return secureblackbox_sshkeymanager_get($this->handle, 1 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getCertCA() {
    return secureblackbox_sshkeymanager_get($this->handle, 2 );
  }
 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  * @param    boolean   value
  */
  public function setCertCA($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getCertCAKeyID() {
    return secureblackbox_sshkeymanager_get($this->handle, 3 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getCertCRLDistributionPoints() {
    return secureblackbox_sshkeymanager_get($this->handle, 4 );
  }
 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertCRLDistributionPoints($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getCertCurve() {
    return secureblackbox_sshkeymanager_get($this->handle, 5 );
  }
 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertCurve($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getCertFingerprint() {
    return secureblackbox_sshkeymanager_get($this->handle, 6 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getCertFriendlyName() {
    return secureblackbox_sshkeymanager_get($this->handle, 7 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertHandle() {
    return secureblackbox_sshkeymanager_get($this->handle, 8 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setCertHandle($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getCertHashAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 9 );
  }
 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  * @param    string   value
  */
  public function setCertHashAlgorithm($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCertIssuer() {
    return secureblackbox_sshkeymanager_get($this->handle, 10 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getCertIssuerRDN() {
    return secureblackbox_sshkeymanager_get($this->handle, 11 );
  }
 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertIssuerRDN($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getCertKeyAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 12 );
  }
 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertKeyAlgorithm($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getCertKeyBits() {
    return secureblackbox_sshkeymanager_get($this->handle, 13 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getCertKeyFingerprint() {
    return secureblackbox_sshkeymanager_get($this->handle, 14 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getCertKeyUsage() {
    return secureblackbox_sshkeymanager_get($this->handle, 15 );
  }
 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertKeyUsage($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getCertKeyValid() {
    return secureblackbox_sshkeymanager_get($this->handle, 16 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getCertOCSPLocations() {
    return secureblackbox_sshkeymanager_get($this->handle, 17 );
  }
 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertOCSPLocations($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the origin of this certificate.
  *
  * @access   public
  */
  public function getCertOrigin() {
    return secureblackbox_sshkeymanager_get($this->handle, 18 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getCertPolicyIDs() {
    return secureblackbox_sshkeymanager_get($this->handle, 19 );
  }
 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertPolicyIDs($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the certificate's private key.
  *
  * @access   public
  */
  public function getCertPrivateKeyBytes() {
    return secureblackbox_sshkeymanager_get($this->handle, 20 );
  }


 /**
  * Indicates whether the certificate has an associated private key.
  *
  * @access   public
  */
  public function getCertPrivateKeyExists() {
    return secureblackbox_sshkeymanager_get($this->handle, 21 );
  }


 /**
  * Indicates whether the private key is extractable.
  *
  * @access   public
  */
  public function getCertPrivateKeyExtractable() {
    return secureblackbox_sshkeymanager_get($this->handle, 22 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getCertPublicKeyBytes() {
    return secureblackbox_sshkeymanager_get($this->handle, 23 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getCertSelfSigned() {
    return secureblackbox_sshkeymanager_get($this->handle, 24 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getCertSerialNumber() {
    return secureblackbox_sshkeymanager_get($this->handle, 25 );
  }
 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSerialNumber($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getCertSigAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 26 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getCertSubject() {
    return secureblackbox_sshkeymanager_get($this->handle, 27 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getCertSubjectKeyID() {
    return secureblackbox_sshkeymanager_get($this->handle, 28 );
  }
 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubjectKeyID($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getCertSubjectRDN() {
    return secureblackbox_sshkeymanager_get($this->handle, 29 );
  }
 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  * @param    string   value
  */
  public function setCertSubjectRDN($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getCertValidFrom() {
    return secureblackbox_sshkeymanager_get($this->handle, 30 );
  }
 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertValidFrom($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getCertValidTo() {
    return secureblackbox_sshkeymanager_get($this->handle, 31 );
  }
 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  * @param    string   value
  */
  public function setCertValidTo($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 31, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getCryptoKeyAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 32 );
  }
 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCryptoKeyAlgorithm($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getCryptoKeyBits() {
    return secureblackbox_sshkeymanager_get($this->handle, 33 );
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getCryptoKeyExportable() {
    return secureblackbox_sshkeymanager_get($this->handle, 34 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCryptoKeyHandle() {
    return secureblackbox_sshkeymanager_get($this->handle, 35 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setCryptoKeyHandle($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getCryptoKeyID() {
    return secureblackbox_sshkeymanager_get($this->handle, 36 );
  }
 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  * @param    string   value
  */
  public function setCryptoKeyID($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getCryptoKeyIV() {
    return secureblackbox_sshkeymanager_get($this->handle, 37 );
  }
 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCryptoKeyIV($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getCryptoKeyKey() {
    return secureblackbox_sshkeymanager_get($this->handle, 38 );
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getCryptoKeyNonce() {
    return secureblackbox_sshkeymanager_get($this->handle, 39 );
  }
 /**
  * A nonce value associated with a key.
  *
  * @access   public
  * @param    string   value
  */
  public function setCryptoKeyNonce($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 39, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getCryptoKeyPrivate() {
    return secureblackbox_sshkeymanager_get($this->handle, 40 );
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getCryptoKeyPublic() {
    return secureblackbox_sshkeymanager_get($this->handle, 41 );
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getCryptoKeySubject() {
    return secureblackbox_sshkeymanager_get($this->handle, 42 );
  }
 /**
  * Returns the key subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setCryptoKeySubject($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 42, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getCryptoKeySymmetric() {
    return secureblackbox_sshkeymanager_get($this->handle, 43 );
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getCryptoKeyValid() {
    return secureblackbox_sshkeymanager_get($this->handle, 44 );
  }


 /**
  * Specifies the key algorithm.
  *
  * @access   public
  */
  public function getKeyAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 45 );
  }


 /**
  * The number of bits in the key: the more the better, 2048 or 4096 are typical values.
  *
  * @access   public
  */
  public function getKeyBits() {
    return secureblackbox_sshkeymanager_get($this->handle, 46 );
  }


 /**
  * The comment for the public key.
  *
  * @access   public
  */
  public function getKeyComment() {
    return secureblackbox_sshkeymanager_get($this->handle, 47 );
  }
 /**
  * The comment for the public key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyComment($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the elliptical curve when EC cryptography is used.
  *
  * @access   public
  */
  public function getKeyCurve() {
    return secureblackbox_sshkeymanager_get($this->handle, 48 );
  }


 /**
  * The G (Generator) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getKeyDSSG() {
    return secureblackbox_sshkeymanager_get($this->handle, 49 );
  }


 /**
  * The P (Prime) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getKeyDSSP() {
    return secureblackbox_sshkeymanager_get($this->handle, 50 );
  }


 /**
  * The Q (Prime Factor) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getKeyDSSQ() {
    return secureblackbox_sshkeymanager_get($this->handle, 51 );
  }


 /**
  * The X (Private key) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getKeyDSSX() {
    return secureblackbox_sshkeymanager_get($this->handle, 52 );
  }


 /**
  * The Y (Public key) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getKeyDSSY() {
    return secureblackbox_sshkeymanager_get($this->handle, 53 );
  }


 /**
  * The value of the secret key (the order of the public key, D) if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getKeyECCD() {
    return secureblackbox_sshkeymanager_get($this->handle, 54 );
  }


 /**
  * The value of the X coordinate of the public key if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getKeyECCQX() {
    return secureblackbox_sshkeymanager_get($this->handle, 55 );
  }


 /**
  * The value of the Y coordinate of the public key if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getKeyECCQY() {
    return secureblackbox_sshkeymanager_get($this->handle, 56 );
  }


 /**
  * The value of the private key if EdDSA (Edwards-curve Digital Signature Algorithm) algorithm is used.
  *
  * @access   public
  */
  public function getKeyEdPrivate() {
    return secureblackbox_sshkeymanager_get($this->handle, 57 );
  }


 /**
  * The value of the public key if EdDSA (Edwards-curve Digital Signature Algorithm) algorithm is used.
  *
  * @access   public
  */
  public function getKeyEdPublic() {
    return secureblackbox_sshkeymanager_get($this->handle, 58 );
  }


 /**
  * Contains the MD5 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getKeyFingerprintMD5() {
    return secureblackbox_sshkeymanager_get($this->handle, 59 );
  }


 /**
  * Contains the SHA-1 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getKeyFingerprintSHA1() {
    return secureblackbox_sshkeymanager_get($this->handle, 60 );
  }


 /**
  * Contains the SHA-256 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getKeyFingerprintSHA256() {
    return secureblackbox_sshkeymanager_get($this->handle, 61 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_sshkeymanager_get($this->handle, 62 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 62, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether the key is extractable (e.
  *
  * @access   public
  */
  public function getKeyIsExtractable() {
    return secureblackbox_sshkeymanager_get($this->handle, 63 );
  }


 /**
  * Whether this key is a private key or not.
  *
  * @access   public
  */
  public function getKeyIsPrivate() {
    return secureblackbox_sshkeymanager_get($this->handle, 64 );
  }


 /**
  * Whether this key is a public key or not.
  *
  * @access   public
  */
  public function getKeyIsPublic() {
    return secureblackbox_sshkeymanager_get($this->handle, 65 );
  }


 /**
  * Returns the number of iterations of the Key Derivation Function (KDF) used to generate this key.
  *
  * @access   public
  */
  public function getKeyKDFRounds() {
    return secureblackbox_sshkeymanager_get($this->handle, 66 );
  }


 /**
  * The salt value used by the Key Derivation Function (KDF) to generate this key.
  *
  * @access   public
  */
  public function getKeyKDFSalt() {
    return secureblackbox_sshkeymanager_get($this->handle, 67 );
  }


 /**
  * Specifies the format in which the key is stored.
  *
  * @access   public
  */
  public function getKeyKeyFormat() {
    return secureblackbox_sshkeymanager_get($this->handle, 68 );
  }


 /**
  * Specifies the key protection algorithm.
  *
  * @access   public
  */
  public function getKeyKeyProtectionAlgorithm() {
    return secureblackbox_sshkeymanager_get($this->handle, 69 );
  }


 /**
  * Returns the e parameter (public exponent) of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAExponent() {
    return secureblackbox_sshkeymanager_get($this->handle, 70 );
  }


 /**
  * Returns the iqmp parameter of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAIQMP() {
    return secureblackbox_sshkeymanager_get($this->handle, 71 );
  }


 /**
  * Returns the m parameter (public modulus) of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAModulus() {
    return secureblackbox_sshkeymanager_get($this->handle, 72 );
  }


 /**
  * Returns the p parameter (first factor of the common modulus n) of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAP() {
    return secureblackbox_sshkeymanager_get($this->handle, 73 );
  }


 /**
  * Returns the d parameter (private exponent) of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAPrivateExponent() {
    return secureblackbox_sshkeymanager_get($this->handle, 74 );
  }


 /**
  * Returns the q parameter (second factor of the common modulus n) of the RSA key.
  *
  * @access   public
  */
  public function getKeyRSAQ() {
    return secureblackbox_sshkeymanager_get($this->handle, 75 );
  }


 /**
  * Specifies the public key owner (subject).
  *
  * @access   public
  */
  public function getKeySubject() {
    return secureblackbox_sshkeymanager_get($this->handle, 76 );
  }
 /**
  * Specifies the public key owner (subject).
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySubject($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_sshkeymanager_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_sshkeymanager_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshkeymanager_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Information about errors during SSH key management.
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
