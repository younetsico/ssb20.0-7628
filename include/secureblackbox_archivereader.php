<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - ArchiveReader Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_ArchiveReader {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_archivereader_open(SECUREBLACKBOX_OEMKEY_822);
    secureblackbox_archivereader_register_callback($this->handle, 1, array($this, 'fireAfterExtractFile'));
    secureblackbox_archivereader_register_callback($this->handle, 2, array($this, 'fireBeforeExtractFile'));
    secureblackbox_archivereader_register_callback($this->handle, 3, array($this, 'fireDecryptionPasswordNeeded'));
    secureblackbox_archivereader_register_callback($this->handle, 4, array($this, 'fireError'));
    secureblackbox_archivereader_register_callback($this->handle, 5, array($this, 'fireNotification'));
    secureblackbox_archivereader_register_callback($this->handle, 6, array($this, 'fireProgress'));
    secureblackbox_archivereader_register_callback($this->handle, 7, array($this, 'fireRecipientFound'));
    secureblackbox_archivereader_register_callback($this->handle, 8, array($this, 'fireSignatureFound'));
  }
  
  public function __destruct() {
    secureblackbox_archivereader_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_archivereader_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_archivereader_get_last_error_code($this->handle);
  }

 /**
  * Closes the current archive.
  *
  * @access   public
  */
  public function doClose() {
    $ret = secureblackbox_archivereader_do_close($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
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
    $ret = secureblackbox_archivereader_do_config($this->handle, $configurationstring);
		$err = secureblackbox_archivereader_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Extracts a single file from the archive.
  *
  * @access   public
  * @param    string    path
  * @param    string    localpath
  * @param    boolean    preservefullpath
  */
  public function doExtract($path, $localpath, $preservefullpath) {
    $ret = secureblackbox_archivereader_do_extract($this->handle, $path, $localpath, $preservefullpath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Extract all the files contained in the archive.
  *
  * @access   public
  * @param    string    outputpath
  */
  public function doExtractAll($outputpath) {
    $ret = secureblackbox_archivereader_do_extractall($this->handle, $outputpath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens an archive file.
  *
  * @access   public
  * @param    int    archivetype
  * @param    string    archivepath
  */
  public function doOpen($archivetype, $archivepath) {
    $ret = secureblackbox_archivereader_do_open($this->handle, $archivetype, $archivepath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads an archive file from a byte array.
  *
  * @access   public
  * @param    int    archivetype
  * @param    string    archivebytes
  */
  public function doOpenBytes($archivetype, $archivebytes) {
    $ret = secureblackbox_archivereader_do_openbytes($this->handle, $archivetype, $archivebytes);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_archivereader_get($this->handle, 0);
  }
 /**
  * The type of the archive file.
  *
  * @access   public
  */
  public function getArchiveType() {
    return secureblackbox_archivereader_get($this->handle, 1 );
  }


 /**
  * The number of records in the DecryptionCert arrays.
  *
  * @access   public
  */
  public function getDecryptionCertCount() {
    return secureblackbox_archivereader_get($this->handle, 2 );
  }
 /**
  * The number of records in the DecryptionCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setDecryptionCertCount($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getDecryptionCertBytes($decryptioncertindex) {
    return secureblackbox_archivereader_get($this->handle, 3 , $decryptioncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getDecryptionCertHandle($decryptioncertindex) {
    return secureblackbox_archivereader_get($this->handle, 4 , $decryptioncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setDecryptionCertHandle($decryptioncertindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 4, $value , $decryptioncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The decryption password.
  *
  * @access   public
  */
  public function getDecryptionPassword() {
    return secureblackbox_archivereader_get($this->handle, 5 );
  }
 /**
  * The decryption password.
  *
  * @access   public
  * @param    string   value
  */
  public function setDecryptionPassword($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The contents of the last extracted file.
  *
  * @access   public
  */
  public function getFileData() {
    return secureblackbox_archivereader_get($this->handle, 6 );
  }
 /**
  * The contents of the last extracted file.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileData($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the File arrays.
  *
  * @access   public
  */
  public function getFileCount() {
    return secureblackbox_archivereader_get($this->handle, 7 );
  }
 /**
  * The number of records in the File arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileCount($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The action to apply to the file.
  *
  * @access   public
  */
  public function getFileAction($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 8 , $fileindex);
  }
 /**
  * The action to apply to the file.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileAction($fileindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 8, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The size of the file after compression.
  *
  * @access   public
  */
  public function getFileCompressedSize($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 9 , $fileindex);
  }


 /**
  * The type of the data source for this entry.
  *
  * @access   public
  */
  public function getFileDataSource($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 10 , $fileindex);
  }
 /**
  * The type of the data source for this entry.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileDataSource($fileindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 10, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Tells if the entry is a directory or a regular file.
  *
  * @access   public
  */
  public function getFileDirectory($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 11 , $fileindex);
  }


 /**
  * Returns the symmetric algorithm that was used to encrypt the file.
  *
  * @access   public
  */
  public function getFileEncryptionAlgorithm($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 12 , $fileindex);
  }


 /**
  * Returns the length, in bits, of the encryption key.
  *
  * @access   public
  */
  public function getFileEncryptionKeyLength($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 13 , $fileindex);
  }


 /**
  * The type of encryption applied to the file.
  *
  * @access   public
  */
  public function getFileEncryptionType($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 14 , $fileindex);
  }


 /**
  * The original name of the compressed file or folder.
  *
  * @access   public
  */
  public function getFileFileName($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 15 , $fileindex);
  }
 /**
  * The original name of the compressed file or folder.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileFileName($fileindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 15, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The containing folder of the entry.
  *
  * @access   public
  */
  public function getFileFolder($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 16 , $fileindex);
  }


 /**
  * The local path associated with this entry.
  *
  * @access   public
  */
  public function getFileLocalPath($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 17 , $fileindex);
  }
 /**
  * The local path associated with this entry.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileLocalPath($fileindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 17, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The entry's last modification time.
  *
  * @access   public
  */
  public function getFileMTime($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 18 , $fileindex);
  }
 /**
  * The entry's last modification time.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileMTime($fileindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 18, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether the entry corresponds to a file to be added to the archive.
  *
  * @access   public
  */
  public function getFileNewFile($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 19 , $fileindex);
  }


 /**
  * The full internal path of the archived entry.
  *
  * @access   public
  */
  public function getFilePath($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 20 , $fileindex);
  }


 /**
  * The number of signatures covering the entry.
  *
  * @access   public
  */
  public function getFileSignatureCount($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 21 , $fileindex);
  }


 /**
  * Indicates whether the entry is signed.
  *
  * @access   public
  */
  public function getFileSigned($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 22 , $fileindex);
  }


 /**
  * The size of the file before compression.
  *
  * @access   public
  */
  public function getFileSize($fileindex) {
    return secureblackbox_archivereader_get($this->handle, 23 , $fileindex);
  }


 /**
  * Returns the hash algorithm that was used to generate the signature.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return secureblackbox_archivereader_get($this->handle, 24 );
  }


 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_archivereader_get($this->handle, 25 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_archivereader_get($this->handle, 26 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_archivereader_get($this->handle, 27 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_archivereader_set($this->handle, 27, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates if the class is in the open state.
  *
  * @access   public
  */
  public function getOpened() {
    return secureblackbox_archivereader_get($this->handle, 28 );
  }


 /**
  * The signature validation result.
  *
  * @access   public
  */
  public function getSignatureValidationResult() {
    return secureblackbox_archivereader_get($this->handle, 29 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_archivereader_get($this->handle, 30 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getSigningCertCA() {
    return secureblackbox_archivereader_get($this->handle, 31 );
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertCAKeyID() {
    return secureblackbox_archivereader_get($this->handle, 32 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getSigningCertCRLDistributionPoints() {
    return secureblackbox_archivereader_get($this->handle, 33 );
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getSigningCertCurve() {
    return secureblackbox_archivereader_get($this->handle, 34 );
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getSigningCertFingerprint() {
    return secureblackbox_archivereader_get($this->handle, 35 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getSigningCertFriendlyName() {
    return secureblackbox_archivereader_get($this->handle, 36 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_archivereader_get($this->handle, 37 );
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getSigningCertHashAlgorithm() {
    return secureblackbox_archivereader_get($this->handle, 38 );
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getSigningCertIssuer() {
    return secureblackbox_archivereader_get($this->handle, 39 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getSigningCertIssuerRDN() {
    return secureblackbox_archivereader_get($this->handle, 40 );
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyAlgorithm() {
    return secureblackbox_archivereader_get($this->handle, 41 );
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getSigningCertKeyBits() {
    return secureblackbox_archivereader_get($this->handle, 42 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyFingerprint() {
    return secureblackbox_archivereader_get($this->handle, 43 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getSigningCertKeyUsage() {
    return secureblackbox_archivereader_get($this->handle, 44 );
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getSigningCertKeyValid() {
    return secureblackbox_archivereader_get($this->handle, 45 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getSigningCertOCSPLocations() {
    return secureblackbox_archivereader_get($this->handle, 46 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getSigningCertPolicyIDs() {
    return secureblackbox_archivereader_get($this->handle, 47 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getSigningCertPublicKeyBytes() {
    return secureblackbox_archivereader_get($this->handle, 48 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getSigningCertSelfSigned() {
    return secureblackbox_archivereader_get($this->handle, 49 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getSigningCertSerialNumber() {
    return secureblackbox_archivereader_get($this->handle, 50 );
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getSigningCertSigAlgorithm() {
    return secureblackbox_archivereader_get($this->handle, 51 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getSigningCertSubject() {
    return secureblackbox_archivereader_get($this->handle, 52 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertSubjectKeyID() {
    return secureblackbox_archivereader_get($this->handle, 53 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getSigningCertSubjectRDN() {
    return secureblackbox_archivereader_get($this->handle, 54 );
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidFrom() {
    return secureblackbox_archivereader_get($this->handle, 55 );
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidTo() {
    return secureblackbox_archivereader_get($this->handle, 56 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_archivereader_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_archivereader_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivereader_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Marks the completion of extraction of an archived file.
  *
  * @access   public
  * @param    array   Array of event parameters: path, filesize, datasource    
  */
  public function fireAfterExtractFile($param) {
    return $param;
  }

 /**
  * Marks the start of extraction of an archived file.
  *
  * @access   public
  * @param    array   Array of event parameters: path, filesize, datasource, extractionpath, skip    
  */
  public function fireBeforeExtractFile($param) {
    return $param;
  }

 /**
  * Requests a decryption password, when needed.
  *
  * @access   public
  * @param    array   Array of event parameters: passwordtarget, cancel    
  */
  public function fireDecryptionPasswordNeeded($param) {
    return $param;
  }

 /**
  * Reports information about errors during archive processing.
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
  * Reports the progress of data extraction.
  *
  * @access   public
  * @param    array   Array of event parameters: processed, total, overallprocessed, overalltotal, cancel    
  */
  public function fireProgress($param) {
    return $param;
  }

 /**
  * Informs the application that an archive is encrypted with a digital certificate.
  *
  * @access   public
  * @param    array   Array of event parameters: recipienthash, certfound    
  */
  public function fireRecipientFound($param) {
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


}

?>
