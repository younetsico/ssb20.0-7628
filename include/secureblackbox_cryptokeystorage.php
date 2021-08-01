<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - CryptoKeyStorage Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_CryptoKeyStorage {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_cryptokeystorage_open(SECUREBLACKBOX_OEMKEY_402);
    secureblackbox_cryptokeystorage_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_cryptokeystorage_register_callback($this->handle, 2, array($this, 'fireNotification'));
    secureblackbox_cryptokeystorage_register_callback($this->handle, 3, array($this, 'firePasswordNeeded'));
  }
  
  public function __destruct() {
    secureblackbox_cryptokeystorage_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_cryptokeystorage_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_cryptokeystorage_get_last_error_code($this->handle);
  }

 /**
  * Adds the pinned key to the storage.
  *
  * @access   public
  */
  public function doAddPinned() {
    $ret = secureblackbox_cryptokeystorage_do_addpinned($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes all existing keys from the storage.
  *
  * @access   public
  */
  public function doClear() {
    $ret = secureblackbox_cryptokeystorage_do_clear($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Closes the logical storage.
  *
  * @access   public
  * @param    boolean    save
  */
  public function doClose($save) {
    $ret = secureblackbox_cryptokeystorage_do_close($this->handle, $save);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
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
    $ret = secureblackbox_cryptokeystorage_do_config($this->handle, $configurationstring);
		$err = secureblackbox_cryptokeystorage_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new storage.
  *
  * @access   public
  * @param    string    storagelocation
  * @param    string    storageid
  */
  public function doCreateNew($storagelocation, $storageid) {
    $ret = secureblackbox_cryptokeystorage_do_createnew($this->handle, $storagelocation, $storageid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds a key to the storage.
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
    $ret = secureblackbox_cryptokeystorage_do_importbytes($this->handle, $value, $format, $keyalgorithm, $scheme, $schemeparams, $keytype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds a key to the storage.
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
    $ret = secureblackbox_cryptokeystorage_do_importfromfile($this->handle, $filename, $format, $keyalgorithm, $scheme, $schemeparams, $keytype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens existing storage or creates one in memory.
  *
  * @access   public
  * @param    string    storageid
  */
  public function doOpen($storageid) {
    $ret = secureblackbox_cryptokeystorage_do_open($this->handle, $storageid);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Refreshes all storage keychains.
  *
  * @access   public
  */
  public function doRefresh() {
    $ret = secureblackbox_cryptokeystorage_do_refresh($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes a key from the storage.
  *
  * @access   public
  * @param    int    index
  */
  public function doRemove($index) {
    $ret = secureblackbox_cryptokeystorage_do_remove($this->handle, $index);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Allows the selection of keys from the store.
  *
  * @access   public
  * @param    string    filter
  * @param    boolean    privatekeyneeded
  * @param    int    maxcount
  */
  public function doSelect($filter, $privatekeyneeded, $maxcount) {
    $ret = secureblackbox_cryptokeystorage_do_select($this->handle, $filter, $privatekeyneeded, $maxcount);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_cryptokeystorage_get($this->handle, 0);
  }
 /**
  * The number of records in the Key arrays.
  *
  * @access   public
  */
  public function getKeyCount() {
    return secureblackbox_cryptokeystorage_get($this->handle, 1 );
  }


 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getKeyAlgorithm($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 2 , $keyindex);
  }


 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getKeyBits($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 3 , $keyindex);
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getKeyExportable($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 4 , $keyindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 5 , $keyindex);
  }


 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getKeyID($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 6 , $keyindex);
  }


 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getKeyIV($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 7 , $keyindex);
  }


 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getKeyKey($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 8 , $keyindex);
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getKeyNonce($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 9 , $keyindex);
  }


 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPrivate($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 10 , $keyindex);
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getKeyPublic($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 11 , $keyindex);
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getKeySubject($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 12 , $keyindex);
  }


 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getKeySymmetric($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 13 , $keyindex);
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getKeyValid($keyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 14 , $keyindex);
  }


 /**
  * Indicates whether the storage is in the open state.
  *
  * @access   public
  */
  public function getOpened() {
    return secureblackbox_cryptokeystorage_get($this->handle, 15 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getPinnedKeyHandle() {
    return secureblackbox_cryptokeystorage_get($this->handle, 16 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setPinnedKeyHandle($value) {
    $ret = secureblackbox_cryptokeystorage_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SelectedKey arrays.
  *
  * @access   public
  */
  public function getSelectedKeyCount() {
    return secureblackbox_cryptokeystorage_get($this->handle, 17 );
  }


 /**
  * The algorithm of the cryptographic key.
  *
  * @access   public
  */
  public function getSelectedKeyAlgorithm($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 18 , $selectedkeyindex);
  }


 /**
  * The length of the key in bits.
  *
  * @access   public
  */
  public function getSelectedKeyBits($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 19 , $selectedkeyindex);
  }


 /**
  * Returns True if the key is exportable (can be serialized into an array of bytes), and False otherwise.
  *
  * @access   public
  */
  public function getSelectedKeyExportable($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 20 , $selectedkeyindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSelectedKeyHandle($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 21 , $selectedkeyindex);
  }


 /**
  * Provides access to a storage-specific key identifier.
  *
  * @access   public
  */
  public function getSelectedKeyID($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 22 , $selectedkeyindex);
  }


 /**
  * The initialization vector (IV) of a symmetric key.
  *
  * @access   public
  */
  public function getSelectedKeyIV($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 23 , $selectedkeyindex);
  }


 /**
  * The byte array representation of the key.
  *
  * @access   public
  */
  public function getSelectedKeyKey($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 24 , $selectedkeyindex);
  }


 /**
  * A nonce value associated with a key.
  *
  * @access   public
  */
  public function getSelectedKeyNonce($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 25 , $selectedkeyindex);
  }


 /**
  * Returns True if the object hosts a private key, and False otherwise.
  *
  * @access   public
  */
  public function getSelectedKeyPrivate($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 26 , $selectedkeyindex);
  }


 /**
  * Returns True if the object hosts a public key, and False otherwise.
  *
  * @access   public
  */
  public function getSelectedKeyPublic($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 27 , $selectedkeyindex);
  }


 /**
  * Returns the key subject.
  *
  * @access   public
  */
  public function getSelectedKeySubject($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 28 , $selectedkeyindex);
  }


 /**
  * Returns True if the object contains a symmetric key, and False otherwise.
  *
  * @access   public
  */
  public function getSelectedKeySymmetric($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 29 , $selectedkeyindex);
  }


 /**
  * Returns True if this key is valid.
  *
  * @access   public
  */
  public function getSelectedKeyValid($selectedkeyindex) {
    return secureblackbox_cryptokeystorage_get($this->handle, 30 , $selectedkeyindex);
  }


 /**
  * A unique identifier of this storage.
  *
  * @access   public
  */
  public function getStorageID() {
    return secureblackbox_cryptokeystorage_get($this->handle, 31 );
  }


 /**
  * Specifies the location of the currently opened storage.
  *
  * @access   public
  */
  public function getStorageLocation() {
    return secureblackbox_cryptokeystorage_get($this->handle, 32 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_cryptokeystorage_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_cryptokeystorage_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_cryptokeystorage_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Fires when an errors happens during a key storage operation.
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
