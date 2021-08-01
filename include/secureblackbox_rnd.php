<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - Rnd Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_Rnd {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_rnd_open(SECUREBLACKBOX_OEMKEY_407);
    secureblackbox_rnd_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_rnd_register_callback($this->handle, 2, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_rnd_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_rnd_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_rnd_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_rnd_do_config($this->handle, $configurationstring);
		$err = secureblackbox_rnd_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates an array of random bytes.
  *
  * @access   public
  * @param    int    len
  */
  public function doNextBytes($len) {
    $ret = secureblackbox_rnd_do_nextbytes($this->handle, $len);
		$err = secureblackbox_rnd_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a random integer.
  *
  * @access   public
  */
  public function doNextInt() {
    $ret = secureblackbox_rnd_do_nextint($this->handle);
		$err = secureblackbox_rnd_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a random password.
  *
  * @access   public
  * @param    boolean    lowercase
  * @param    boolean    uppercase
  * @param    boolean    digits
  * @param    boolean    specials
  * @param    int    len
  */
  public function doNextPass($lowercase, $uppercase, $digits, $specials, $len) {
    $ret = secureblackbox_rnd_do_nextpass($this->handle, $lowercase, $uppercase, $digits, $specials, $len);
		$err = secureblackbox_rnd_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Generates a random string of characters.
  *
  * @access   public
  * @param    int    len
  */
  public function doNextString($len) {
    $ret = secureblackbox_rnd_do_nextstring($this->handle, $len);
		$err = secureblackbox_rnd_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Seeds the random generator with a system-originating input.
  *
  * @access   public
  */
  public function doRandomize() {
    $ret = secureblackbox_rnd_do_randomize($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Seeds the generator with a data in a byte array.
  *
  * @access   public
  * @param    string    value
  */
  public function doSeedBytes($value) {
    $ret = secureblackbox_rnd_do_seedbytes($this->handle, $value);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Seeds the generator with an integer value.
  *
  * @access   public
  * @param    int    intvalue
  */
  public function doSeedInt($intvalue) {
    $ret = secureblackbox_rnd_do_seedint($this->handle, $intvalue);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Seeds the generator with a string value.
  *
  * @access   public
  * @param    string    strvalue
  */
  public function doSeedString($strvalue) {
    $ret = secureblackbox_rnd_do_seedstring($this->handle, $strvalue);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Seeds the generator with current time.
  *
  * @access   public
  */
  public function doSeedTime() {
    $ret = secureblackbox_rnd_do_seedtime($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_rnd_get($this->handle, 0);
  }
 /**
  * Alphabet to use for random string generation.
  *
  * @access   public
  */
  public function getAlphabet() {
    return secureblackbox_rnd_get($this->handle, 1 );
  }
 /**
  * Alphabet to use for random string generation.
  *
  * @access   public
  * @param    string   value
  */
  public function setAlphabet($value) {
    $ret = secureblackbox_rnd_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_rnd_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_rnd_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_rnd_get_last_error($this->handle));
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
