<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - HashFunction Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_HashFunction {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_hashfunction_open(SECUREBLACKBOX_OEMKEY_406);
    secureblackbox_hashfunction_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_hashfunction_register_callback($this->handle, 2, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_hashfunction_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_hashfunction_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_hashfunction_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_hashfunction_do_config($this->handle, $configurationstring);
		$err = secureblackbox_hashfunction_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Completes the hash and returns the resulting message digest.
  *
  * @access   public
  */
  public function doFinish() {
    $ret = secureblackbox_hashfunction_do_finish($this->handle);
		$err = secureblackbox_hashfunction_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Calculates a message digest over a byte array.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doHash($buffer) {
    $ret = secureblackbox_hashfunction_do_hash($this->handle, $buffer);
		$err = secureblackbox_hashfunction_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Calculates a message digest over data contained in a file.
  *
  * @access   public
  * @param    string    sourcefile
  */
  public function doHashFile($sourcefile) {
    $ret = secureblackbox_hashfunction_do_hashfile($this->handle, $sourcefile);
		$err = secureblackbox_hashfunction_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Calculates a message digest over data contained in a stream.
  *
  * @access   public
  */
  public function doHashStream() {
    $ret = secureblackbox_hashfunction_do_hashstream($this->handle);
		$err = secureblackbox_hashfunction_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the hash function context.
  *
  * @access   public
  */
  public function doReset() {
    $ret = secureblackbox_hashfunction_do_reset($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Feeds a chunk of data to the hash function.
  *
  * @access   public
  * @param    string    buffer
  */
  public function doUpdate($buffer) {
    $ret = secureblackbox_hashfunction_do_update($this->handle, $buffer);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Feeds the contents of a file to the hash function.
  *
  * @access   public
  * @param    string    sourcefile
  */
  public function doUpdateFile($sourcefile) {
    $ret = secureblackbox_hashfunction_do_updatefile($this->handle, $sourcefile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Feeds the contents of a stream to the hash function.
  *
  * @access   public
  */
  public function doUpdateStream() {
    $ret = secureblackbox_hashfunction_do_updatestream($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_hashfunction_get($this->handle, 0);
  }
 /**
  * The hash algorithm to use when hashing data.
  *
  * @access   public
  */
  public function getAlgorithm() {
    return secureblackbox_hashfunction_get($this->handle, 1 );
  }
 /**
  * The hash algorithm to use when hashing data.
  *
  * @access   public
  * @param    string   value
  */
  public function setAlgorithm($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains key header parameters.
  *
  * @access   public
  */
  public function getJsonKeyHeaderParams() {
    return secureblackbox_hashfunction_get($this->handle, 2 );
  }
 /**
  * Contains key header parameters.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonKeyHeaderParams($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the header being protected.
  *
  * @access   public
  */
  public function getJsonProtectedHeader() {
    return secureblackbox_hashfunction_get($this->handle, 3 );
  }
 /**
  * Provides access to the header being protected.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonProtectedHeader($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the unprotected part of the header.
  *
  * @access   public
  */
  public function getJsonUnprotectedHeader() {
    return secureblackbox_hashfunction_get($this->handle, 4 );
  }
 /**
  * Provides access to the unprotected part of the header.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonUnprotectedHeader($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains unprotected header parameters.
  *
  * @access   public
  */
  public function getJsonUnprotectedHeaderParams() {
    return secureblackbox_hashfunction_get($this->handle, 5 );
  }
 /**
  * Contains unprotected header parameters.
  *
  * @access   public
  * @param    string   value
  */
  public function setJsonUnprotectedHeaderParams($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getKeyAlgorithm() {
    return secureblackbox_hashfunction_get($this->handle, 6 );
  }
 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyAlgorithm($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getKeyBits() {
    return secureblackbox_hashfunction_get($this->handle, 7 );
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getKeyExportable() {
    return secureblackbox_hashfunction_get($this->handle, 8 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_hashfunction_get($this->handle, 9 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getKeyID() {
    return secureblackbox_hashfunction_get($this->handle, 10 );
  }
 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyID($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getKeyIV() {
    return secureblackbox_hashfunction_get($this->handle, 11 );
  }
 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyIV($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getKeyKey() {
    return secureblackbox_hashfunction_get($this->handle, 12 );
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getKeyNonce() {
    return secureblackbox_hashfunction_get($this->handle, 13 );
  }
 /**
  * A nonce value associated with a key.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeyNonce($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPrivate() {
    return secureblackbox_hashfunction_get($this->handle, 14 );
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPublic() {
    return secureblackbox_hashfunction_get($this->handle, 15 );
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getKeySubject() {
    return secureblackbox_hashfunction_get($this->handle, 16 );
  }
 /**
  * Returns the key subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setKeySubject($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getKeySymmetric() {
    return secureblackbox_hashfunction_get($this->handle, 17 );
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getKeyValid() {
    return secureblackbox_hashfunction_get($this->handle, 18 );
  }


 /**
  * The encoding to use for the output data.
  *
  * @access   public
  */
  public function getOutputEncoding() {
    return secureblackbox_hashfunction_get($this->handle, 19 );
  }
 /**
  * The encoding to use for the output data.
  *
  * @access   public
  * @param    int   value
  */
  public function setOutputEncoding($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_hashfunction_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_hashfunction_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_hashfunction_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Informs about errors during cryptographic operations.
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
