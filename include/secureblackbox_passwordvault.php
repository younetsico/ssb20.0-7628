<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - PasswordVault Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_PasswordVault {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_passwordvault_open(SECUREBLACKBOX_OEMKEY_411);
    secureblackbox_passwordvault_register_callback($this->handle, 1, array($this, 'fireEntryKeyNeeded'));
    secureblackbox_passwordvault_register_callback($this->handle, 2, array($this, 'fireError'));
    secureblackbox_passwordvault_register_callback($this->handle, 3, array($this, 'fireKeyNeeded'));
    secureblackbox_passwordvault_register_callback($this->handle, 4, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_passwordvault_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_passwordvault_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_passwordvault_get_last_error_code($this->handle);
  }

 /**
  * Adds an entry to the vault.
  *
  * @access   public
  * @param    string    entryname
  */
  public function doAddEntry($entryname) {
    $ret = secureblackbox_passwordvault_do_addentry($this->handle, $entryname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Changes the entry's encryption key.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    newkey
  */
  public function doChangeEntryKey($entryname, $newkey) {
    $ret = secureblackbox_passwordvault_do_changeentrykey($this->handle, $entryname, $newkey);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Changes the entry's encryption password.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    newpassword
  */
  public function doChangeEntryPassword($entryname, $newpassword) {
    $ret = secureblackbox_passwordvault_do_changeentrypassword($this->handle, $entryname, $newpassword);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Closes the vault file.
  *
  * @access   public
  */
  public function doClose() {
    $ret = secureblackbox_passwordvault_do_close($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
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
    $ret = secureblackbox_passwordvault_do_config($this->handle, $configurationstring);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the content stored in one of the entry fields as a byte array.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    fieldname
  */
  public function doGetEntryValue($entryname, $fieldname) {
    $ret = secureblackbox_passwordvault_do_getentryvalue($this->handle, $entryname, $fieldname);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the content stored in a field of the entry as a string.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    fieldname
  */
  public function doGetEntryValueStr($entryname, $fieldname) {
    $ret = secureblackbox_passwordvault_do_getentryvaluestr($this->handle, $entryname, $fieldname);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns a list of entries stored in the vault.
  *
  * @access   public
  */
  public function doListEntries() {
    $ret = secureblackbox_passwordvault_do_listentries($this->handle);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns a list of fields contained in the entry.
  *
  * @access   public
  * @param    string    entryname
  * @param    boolean    includeencrypted
  */
  public function doListFields($entryname, $includeencrypted) {
    $ret = secureblackbox_passwordvault_do_listfields($this->handle, $entryname, $includeencrypted);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Loads vault content from a byte array.
  *
  * @access   public
  * @param    string    vaultbytes
  */
  public function doOpenBytes($vaultbytes) {
    $ret = secureblackbox_passwordvault_do_openbytes($this->handle, $vaultbytes);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens a vault file.
  *
  * @access   public
  * @param    string    filename
  */
  public function doOpenFile($filename) {
    $ret = secureblackbox_passwordvault_do_openfile($this->handle, $filename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes all entries from a vault.
  *
  * @access   public
  */
  public function doRemoveAllEntries() {
    $ret = secureblackbox_passwordvault_do_removeallentries($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes an entry from the vault.
  *
  * @access   public
  * @param    string    entryname
  */
  public function doRemoveEntry($entryname) {
    $ret = secureblackbox_passwordvault_do_removeentry($this->handle, $entryname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes an entry field.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    fieldname
  */
  public function doRemoveField($entryname, $fieldname) {
    $ret = secureblackbox_passwordvault_do_removefield($this->handle, $entryname, $fieldname);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the vault contents to a byte array.
  *
  * @access   public
  */
  public function doSaveBytes() {
    $ret = secureblackbox_passwordvault_do_savebytes($this->handle);
		$err = secureblackbox_passwordvault_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the vault contents to a file.
  *
  * @access   public
  * @param    string    filename
  */
  public function doSaveFile($filename) {
    $ret = secureblackbox_passwordvault_do_savefile($this->handle, $filename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Assigns a value to an entry field.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    fieldname
  * @param    string    fieldvalue
  * @param    boolean    encrypted
  */
  public function doSetEntryValue($entryname, $fieldname, $fieldvalue, $encrypted) {
    $ret = secureblackbox_passwordvault_do_setentryvalue($this->handle, $entryname, $fieldname, $fieldvalue, $encrypted);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Assigns a value to an entry field.
  *
  * @access   public
  * @param    string    entryname
  * @param    string    fieldname
  * @param    string    fieldvaluestr
  * @param    boolean    encrypted
  */
  public function doSetEntryValueStr($entryname, $fieldname, $fieldvaluestr, $encrypted) {
    $ret = secureblackbox_passwordvault_do_setentryvaluestr($this->handle, $entryname, $fieldname, $fieldvaluestr, $encrypted);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_passwordvault_get($this->handle, 0);
  }
 /**
  * The description of the vault.
  *
  * @access   public
  */
  public function getDescription() {
    return secureblackbox_passwordvault_get($this->handle, 1 );
  }
 /**
  * The description of the vault.
  *
  * @access   public
  * @param    string   value
  */
  public function setDescription($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides an encryption key for the current entry.
  *
  * @access   public
  */
  public function getEntryKey() {
    return secureblackbox_passwordvault_get($this->handle, 2 );
  }
 /**
  * Provides an encryption key for the current entry.
  *
  * @access   public
  * @param    string   value
  */
  public function setEntryKey($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides an encryption password for the current entry.
  *
  * @access   public
  */
  public function getEntryPassword() {
    return secureblackbox_passwordvault_get($this->handle, 3 );
  }
 /**
  * Provides an encryption password for the current entry.
  *
  * @access   public
  * @param    string   value
  */
  public function setEntryPassword($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides an encryption key for the vault.
  *
  * @access   public
  */
  public function getKey() {
    return secureblackbox_passwordvault_get($this->handle, 4 );
  }
 /**
  * Provides an encryption key for the vault.
  *
  * @access   public
  * @param    string   value
  */
  public function setKey($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 4, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides an encryption password for the vault file.
  *
  * @access   public
  */
  public function getPassword() {
    return secureblackbox_passwordvault_get($this->handle, 5 );
  }
 /**
  * Provides an encryption password for the vault file.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables platform-based protection of the master key.
  *
  * @access   public
  */
  public function getPlatformProtection() {
    return secureblackbox_passwordvault_get($this->handle, 6 );
  }
 /**
  * Enables platform-based protection of the master key.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setPlatformProtection($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The title of the vault.
  *
  * @access   public
  */
  public function getTitle() {
    return secureblackbox_passwordvault_get($this->handle, 7 );
  }
 /**
  * The title of the vault.
  *
  * @access   public
  * @param    string   value
  */
  public function setTitle($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_passwordvault_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_passwordvault_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_passwordvault_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * This event is fired to request an entry encryption/decryption key from the application.
  *
  * @access   public
  * @param    array   Array of event parameters: entryname, cancel    
  */
  public function fireEntryKeyNeeded($param) {
    return $param;
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
  * This event is fired to request a vault encryption/decryption key from the application.
  *
  * @access   public
  * @param    array   Array of event parameters: cancel    
  */
  public function fireKeyNeeded($param) {
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
