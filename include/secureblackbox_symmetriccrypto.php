<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SymmetricCrypto Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SymmetricCrypto {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_symmetriccrypto_open(SECUREBLACKBOX_OEMKEY_404);
    secureblackbox_symmetriccrypto_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_symmetriccrypto_register_callback($this->handle, 2, array($this, 'fireNotification'));
    secureblackbox_symmetriccrypto_register_callback($this->handle, 3, array($this, 'fireProgress'));
  }
  
  public function __destruct() {
    secureblackbox_symmetriccrypto_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_symmetriccrypto_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_symmetriccrypto_do_config($this->handle, $configurationstring);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts a buffer.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doDecrypt($buffer) {
    $ret = secureblackbox_symmetriccrypto_do_decrypt($this->handle, $buffer);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts a file.
  *
  * @access   public
  * @param    string    sourcefile
  * @param    string    destfile
  */
  public function doDecryptFile($sourcefile, $destfile) {
    $ret = secureblackbox_symmetriccrypto_do_decryptfile($this->handle, $sourcefile, $destfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Finalization of decryption by blocks.
  *
  * @access   public
  */
  public function doDecryptFinal() {
    $ret = secureblackbox_symmetriccrypto_do_decryptfinal($this->handle);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Initializes a per-block decryption process.
  *
  * @access   public
  */
  public function doDecryptInit() {
    $ret = secureblackbox_symmetriccrypto_do_decryptinit($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Decrypts the next block of encrypted data.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doDecryptUpdate($buffer) {
    $ret = secureblackbox_symmetriccrypto_do_decryptupdate($this->handle, $buffer);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts a buffer.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doEncrypt($buffer) {
    $ret = secureblackbox_symmetriccrypto_do_encrypt($this->handle, $buffer);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts a file.
  *
  * @access   public
  * @param    string    sourcefile
  * @param    string    destfile
  */
  public function doEncryptFile($sourcefile, $destfile) {
    $ret = secureblackbox_symmetriccrypto_do_encryptfile($this->handle, $sourcefile, $destfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Finalization of encryption by blocks.
  *
  * @access   public
  */
  public function doEncryptFinal() {
    $ret = secureblackbox_symmetriccrypto_do_encryptfinal($this->handle);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Initializes a per-block encryption process.
  *
  * @access   public
  */
  public function doEncryptInit() {
    $ret = secureblackbox_symmetriccrypto_do_encryptinit($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Encrypts the next block of data.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doEncryptUpdate($buffer) {
    $ret = secureblackbox_symmetriccrypto_do_encryptupdate($this->handle, $buffer);
		$err = secureblackbox_symmetriccrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_symmetriccrypto_get($this->handle, 0);
  }
 /**
  * Provides Associated Data for AEAD algorithms.
  *
  * @access   public
  */
  public function getAssociatedData() {
    return secureblackbox_symmetriccrypto_get($this->handle, 1 );
  }
 /**
  * Provides Associated Data for AEAD algorithms.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssociatedData($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The block size of the chosen symmetric cipher.
  *
  * @access   public
  */
  public function getBlockSize() {
    return secureblackbox_symmetriccrypto_get($this->handle, 2 );
  }


 /**
  * The encryption algorithm to use for encrypting the data.
  *
  * @access   public
  */
  public function getEncryptionAlgorithm() {
    return secureblackbox_symmetriccrypto_get($this->handle, 3 );
  }
 /**
  * The encryption algorithm to use for encrypting the data.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptionAlgorithm($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The hash algorithm to use during encryption.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return secureblackbox_symmetriccrypto_get($this->handle, 4 );
  }
 /**
  * The hash algorithm to use during encryption.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashAlgorithm($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The encoding to apply to the input data.
  *
  * @access   public
  */
  public function getInputEncoding() {
    return secureblackbox_symmetriccrypto_get($this->handle, 5 );
  }
 /**
  * The encoding to apply to the input data.
  *
  * @access   public
  * @param    int   value
  */
  public function setInputEncoding($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getKeyAlgorithm() {
    return secureblackbox_symmetriccrypto_get($this->handle, 6 );
  }
 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyAlgorithm($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getKeyBits() {
    return secureblackbox_symmetriccrypto_get($this->handle, 7 );
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getKeyExportable() {
    return secureblackbox_symmetriccrypto_get($this->handle, 8 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_symmetriccrypto_get($this->handle, 9 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getKeyID() {
    return secureblackbox_symmetriccrypto_get($this->handle, 10 );
  }
 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyID($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getKeyIV() {
    return secureblackbox_symmetriccrypto_get($this->handle, 11 );
  }
 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyIV($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getKeyKey() {
    return secureblackbox_symmetriccrypto_get($this->handle, 12 );
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getKeyNonce() {
    return secureblackbox_symmetriccrypto_get($this->handle, 13 );
  }
 /**
  * A nonce value associated with a key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyNonce($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPrivate() {
    return secureblackbox_symmetriccrypto_get($this->handle, 14 );
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPublic() {
    return secureblackbox_symmetriccrypto_get($this->handle, 15 );
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getKeySubject() {
    return secureblackbox_symmetriccrypto_get($this->handle, 16 );
  }
 /**
  * Returns the key subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySubject($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getKeySymmetric() {
    return secureblackbox_symmetriccrypto_get($this->handle, 17 );
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getKeyValid() {
    return secureblackbox_symmetriccrypto_get($this->handle, 18 );
  }


 /**
  * Returns the cryptographic key size in bytes.
  *
  * @access   public
  */
  public function getKeySize() {
    return secureblackbox_symmetriccrypto_get($this->handle, 19 );
  }


 /**
  * The (H)MAC algorithm to use during encryption.
  *
  * @access   public
  */
  public function getMACAlgorithm() {
    return secureblackbox_symmetriccrypto_get($this->handle, 20 );
  }
 /**
  * The (H)MAC algorithm to use during encryption.
  *
  * @access   public
  * @param    string   value
  */
  public function setMACAlgorithm($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the symmetric cipher mode of operation.
  *
  * @access   public
  */
  public function getMode() {
    return secureblackbox_symmetriccrypto_get($this->handle, 21 );
  }
 /**
  * Specifies the symmetric cipher mode of operation.
  *
  * @access   public
  * @param    int   value
  */
  public function setMode($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the Nonce value to employ.
  *
  * @access   public
  */
  public function getNonce() {
    return secureblackbox_symmetriccrypto_get($this->handle, 22 );
  }
 /**
  * Specifies the Nonce value to employ.
  *
  * @access   public
  * @param    string   value
  */
  public function setNonce($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The encoding to apply to the output data.
  *
  * @access   public
  */
  public function getOutputEncoding() {
    return secureblackbox_symmetriccrypto_get($this->handle, 23 );
  }
 /**
  * The encoding to apply to the output data.
  *
  * @access   public
  * @param    int   value
  */
  public function setOutputEncoding($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The padding type to apply to the encrypted data.
  *
  * @access   public
  */
  public function getPadding() {
    return secureblackbox_symmetriccrypto_get($this->handle, 24 );
  }
 /**
  * The padding type to apply to the encrypted data.
  *
  * @access   public
  * @param    int   value
  */
  public function setPadding($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the payload size, in bytes.
  *
  * @access   public
  */
  public function getPayloadSize() {
    return secureblackbox_symmetriccrypto_get($this->handle, 25 );
  }
 /**
  * Specifies the payload size, in bytes.
  *
  * @access   public
  * @param    int   value
  */
  public function setPayloadSize($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns true if the selected algorithms works as a stream cipher.
  *
  * @access   public
  */
  public function getStreamCipher() {
    return secureblackbox_symmetriccrypto_get($this->handle, 26 );
  }


 /**
  * Specifies the AEAD tag size, in bytes.
  *
  * @access   public
  */
  public function getTagSize() {
    return secureblackbox_symmetriccrypto_get($this->handle, 27 );
  }
 /**
  * Specifies the AEAD tag size, in bytes.
  *
  * @access   public
  * @param    int   value
  */
  public function setTagSize($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_symmetriccrypto_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_symmetriccrypto_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_symmetriccrypto_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Reports errors during encryption or decryption.
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
  * Reports the data encryption/decryption progress.
  *
  * @access   public
  * @param    array   Array of event parameters: total, current, cancel    
  */
  public function fireProgress($param) {
    return $param;
  }


}

?>
