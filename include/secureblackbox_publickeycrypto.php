<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - PublicKeyCrypto Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_PublicKeyCrypto {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_publickeycrypto_open(SECUREBLACKBOX_OEMKEY_405);
    secureblackbox_publickeycrypto_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_publickeycrypto_register_callback($this->handle, 2, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_publickeycrypto_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_publickeycrypto_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_publickeycrypto_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_publickeycrypto_do_config($this->handle, $configurationstring);
		$err = secureblackbox_publickeycrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
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
    $ret = secureblackbox_publickeycrypto_do_decrypt($this->handle, $buffer);
		$err = secureblackbox_publickeycrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
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
    $ret = secureblackbox_publickeycrypto_do_decryptfile($this->handle, $sourcefile, $destfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
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
    $ret = secureblackbox_publickeycrypto_do_encrypt($this->handle, $buffer);
		$err = secureblackbox_publickeycrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
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
    $ret = secureblackbox_publickeycrypto_do_encryptfile($this->handle, $sourcefile, $destfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs a buffer.
  *
  * @access   public
  * @param    string    buffer
  * @param    boolean    detached
  */
  public function doSign($buffer, $detached) {
    $ret = secureblackbox_publickeycrypto_do_sign($this->handle, $buffer, $detached);
		$err = secureblackbox_publickeycrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Signs a file.
  *
  * @access   public
  * @param    string    sourcefile
  * @param    string    destfile
  * @param    boolean    detached
  */
  public function doSignFile($sourcefile, $destfile, $detached) {
    $ret = secureblackbox_publickeycrypto_do_signfile($this->handle, $sourcefile, $destfile, $detached);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies an enveloped or enveloping signature contained in a buffer.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doVerify($buffer) {
    $ret = secureblackbox_publickeycrypto_do_verify($this->handle, $buffer);
		$err = secureblackbox_publickeycrypto_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies a detached signature.
  *
  * @access   public
  * @param    string    signeddata
  * @param    string    signature
  */
  public function doVerifyDetached($signeddata, $signature) {
    $ret = secureblackbox_publickeycrypto_do_verifydetached($this->handle, $signeddata, $signature);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies a detached signature.
  *
  * @access   public
  * @param    string    signeddatafile
  * @param    string    signaturefile
  */
  public function doVerifyDetachedFile($signeddatafile, $signaturefile) {
    $ret = secureblackbox_publickeycrypto_do_verifydetachedfile($this->handle, $signeddatafile, $signaturefile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Verifies an enveloped or enveloping signature contained in a file.
  *
  * @access   public
  * @param    string    sourcefile
  * @param    string    destfile
  */
  public function doVerifyFile($sourcefile, $destfile) {
    $ret = secureblackbox_publickeycrypto_do_verifyfile($this->handle, $sourcefile, $destfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_publickeycrypto_get($this->handle, 0);
  }
 /**
  * Returns true if the crypto object can be used for encryption.
  *
  * @access   public
  */
  public function getCanEncrypt() {
    return secureblackbox_publickeycrypto_get($this->handle, 1 );
  }


 /**
  * Returns true if the crypto object is capable of data signing.
  *
  * @access   public
  */
  public function getCanSign() {
    return secureblackbox_publickeycrypto_get($this->handle, 2 );
  }


 /**
  * The hash algorithm to be used during the crypto operation.
  *
  * @access   public
  */
  public function getHashAlgorithm() {
    return secureblackbox_publickeycrypto_get($this->handle, 3 );
  }
 /**
  * The hash algorithm to be used during the crypto operation.
  *
  * @access   public
  * @param    string   value
  */
  public function setHashAlgorithm($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The encoding to apply to the input data.
  *
  * @access   public
  */
  public function getInputEncoding() {
    return secureblackbox_publickeycrypto_get($this->handle, 4 );
  }
 /**
  * The encoding to apply to the input data.
  *
  * @access   public
  * @param    int   value
  */
  public function setInputEncoding($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether the input data contains the hash or the actual data.
  *
  * @access   public
  */
  public function getInputIsHash() {
    return secureblackbox_publickeycrypto_get($this->handle, 5 );
  }
 /**
  * Indicates whether the input data contains the hash or the actual data.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setInputIsHash($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains key header parameters.
  *
  * @access   public
  */
  public function getJsonKeyHeaderParams() {
    return secureblackbox_publickeycrypto_get($this->handle, 6 );
  }
 /**
  * Contains key header parameters.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonKeyHeaderParams($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the header being protected.
  *
  * @access   public
  */
  public function getJsonProtectedHeader() {
    return secureblackbox_publickeycrypto_get($this->handle, 7 );
  }
 /**
  * Provides access to the header being protected.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonProtectedHeader($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the unprotected part of the header.
  *
  * @access   public
  */
  public function getJsonUnprotectedHeader() {
    return secureblackbox_publickeycrypto_get($this->handle, 8 );
  }
 /**
  * Provides access to the unprotected part of the header.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonUnprotectedHeader($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains unprotected header parameters.
  *
  * @access   public
  */
  public function getJsonUnprotectedHeaderParams() {
    return secureblackbox_publickeycrypto_get($this->handle, 9 );
  }
 /**
  * Contains unprotected header parameters.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonUnprotectedHeaderParams($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getKeyAlgorithm() {
    return secureblackbox_publickeycrypto_get($this->handle, 10 );
  }
 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyAlgorithm($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getKeyBits() {
    return secureblackbox_publickeycrypto_get($this->handle, 11 );
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getKeyExportable() {
    return secureblackbox_publickeycrypto_get($this->handle, 12 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_publickeycrypto_get($this->handle, 13 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getKeyID() {
    return secureblackbox_publickeycrypto_get($this->handle, 14 );
  }
 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyID($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getKeyIV() {
    return secureblackbox_publickeycrypto_get($this->handle, 15 );
  }
 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyIV($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getKeyKey() {
    return secureblackbox_publickeycrypto_get($this->handle, 16 );
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getKeyNonce() {
    return secureblackbox_publickeycrypto_get($this->handle, 17 );
  }
 /**
  * A nonce value associated with a key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyNonce($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPrivate() {
    return secureblackbox_publickeycrypto_get($this->handle, 18 );
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPublic() {
    return secureblackbox_publickeycrypto_get($this->handle, 19 );
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getKeySubject() {
    return secureblackbox_publickeycrypto_get($this->handle, 20 );
  }
 /**
  * Returns the key subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySubject($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getKeySymmetric() {
    return secureblackbox_publickeycrypto_get($this->handle, 21 );
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getKeyValid() {
    return secureblackbox_publickeycrypto_get($this->handle, 22 );
  }


 /**
  * The encoding type to apply to the output data.
  *
  * @access   public
  */
  public function getOutputEncoding() {
    return secureblackbox_publickeycrypto_get($this->handle, 23 );
  }
 /**
  * The encoding type to apply to the output data.
  *
  * @access   public
  * @param    int   value
  */
  public function setOutputEncoding($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm scheme to use.
  *
  * @access   public
  */
  public function getScheme() {
    return secureblackbox_publickeycrypto_get($this->handle, 24 );
  }
 /**
  * The algorithm scheme to use.
  *
  * @access   public
  * @param    string   value
  */
  public function setScheme($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 24, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm scheme parameters to employ.
  *
  * @access   public
  */
  public function getSchemeParams() {
    return secureblackbox_publickeycrypto_get($this->handle, 25 );
  }
 /**
  * The algorithm scheme parameters to employ.
  *
  * @access   public
  * @param    string   value
  */
  public function setSchemeParams($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The signature validation result.
  *
  * @access   public
  */
  public function getSignatureValidationResult() {
    return secureblackbox_publickeycrypto_get($this->handle, 26 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_publickeycrypto_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_publickeycrypto_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_publickeycrypto_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Reports error information during a crypto operation.
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
