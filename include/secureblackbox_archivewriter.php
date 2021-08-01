<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - ArchiveWriter Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_ArchiveWriter {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_archivewriter_open(SECUREBLACKBOX_OEMKEY_821);
    secureblackbox_archivewriter_register_callback($this->handle, 1, array($this, 'fireAfterCompressFile'));
    secureblackbox_archivewriter_register_callback($this->handle, 2, array($this, 'fireBeforeCompressFile'));
    secureblackbox_archivewriter_register_callback($this->handle, 3, array($this, 'fireDecryptionPasswordNeeded'));
    secureblackbox_archivewriter_register_callback($this->handle, 4, array($this, 'fireError'));
    secureblackbox_archivewriter_register_callback($this->handle, 5, array($this, 'fireNotification'));
    secureblackbox_archivewriter_register_callback($this->handle, 6, array($this, 'firePrepareFile'));
    secureblackbox_archivewriter_register_callback($this->handle, 7, array($this, 'fireProgress'));
    secureblackbox_archivewriter_register_callback($this->handle, 8, array($this, 'fireRecipientFound'));
  }
  
  public function __destruct() {
    secureblackbox_archivewriter_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_archivewriter_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_archivewriter_get_last_error_code($this->handle);
  }

 /**
  * Adds an empty folder to the archive.
  *
  * @access   public
  * @param    string    path
  */
  public function doAddEmptyDir($path) {
    $ret = secureblackbox_archivewriter_do_addemptydir($this->handle, $path);
		$err = secureblackbox_archivewriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds a file to the archive.
  *
  * @access   public
  * @param    string    path
  * @param    string    localpath
  */
  public function doAddFile($path, $localpath) {
    $ret = secureblackbox_archivewriter_do_addfile($this->handle, $path, $localpath);
		$err = secureblackbox_archivewriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds a group of files to the archive.
  *
  * @access   public
  * @param    string    folder
  * @param    string    localpath
  * @param    boolean    recursive
  */
  public function doAddFiles($folder, $localpath, $recursive) {
    $ret = secureblackbox_archivewriter_do_addfiles($this->handle, $folder, $localpath, $recursive);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds a file placeholder to the archive.
  *
  * @access   public
  * @param    string    path
  */
  public function doAddVirtual($path) {
    $ret = secureblackbox_archivewriter_do_addvirtual($this->handle, $path);
		$err = secureblackbox_archivewriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Closes the archive.
  *
  * @access   public
  */
  public function doClose() {
    $ret = secureblackbox_archivewriter_do_close($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
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
    $ret = secureblackbox_archivewriter_do_config($this->handle, $configurationstring);
		$err = secureblackbox_archivewriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new archive.
  *
  * @access   public
  * @param    int    archivetype
  */
  public function doCreateNew($archivetype) {
    $ret = secureblackbox_archivewriter_do_createnew($this->handle, $archivetype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens an archive file.
  *
  * @access   public
  * @param    int    archivetype
  * @param    string    archivename
  */
  public function doOpen($archivetype, $archivename) {
    $ret = secureblackbox_archivewriter_do_open($this->handle, $archivetype, $archivename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
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
    $ret = secureblackbox_archivewriter_do_openbytes($this->handle, $archivetype, $archivebytes);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes file(s) and/or folder(s) from the archive.
  *
  * @access   public
  * @param    string    path
  */
  public function doRemove($path) {
    $ret = secureblackbox_archivewriter_do_remove($this->handle, $path);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Compresses the archive and saves it to a file.
  *
  * @access   public
  * @param    string    archivename
  */
  public function doSave($archivename) {
    $ret = secureblackbox_archivewriter_do_save($this->handle, $archivename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Compresses the archive and saves it to a byte array.
  *
  * @access   public
  */
  public function doSaveBytes() {
    $ret = secureblackbox_archivewriter_do_savebytes($this->handle);
		$err = secureblackbox_archivewriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Updates an existing compressed entry with a fresher local version.
  *
  * @access   public
  * @param    string    path
  * @param    string    localpath
  */
  public function doUpdateFile($path, $localpath) {
    $ret = secureblackbox_archivewriter_do_updatefile($this->handle, $path, $localpath);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Updates a selection of files in the archive.
  *
  * @access   public
  * @param    string    folder
  * @param    string    localpath
  * @param    boolean    addmissingfiles
  * @param    boolean    removemissingfiles
  * @param    boolean    recursive
  */
  public function doUpdateFiles($folder, $localpath, $addmissingfiles, $removemissingfiles, $recursive) {
    $ret = secureblackbox_archivewriter_do_updatefiles($this->handle, $folder, $localpath, $addmissingfiles, $removemissingfiles, $recursive);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Updates an entry in the archive with on-the-fly content.
  *
  * @access   public
  * @param    string    path
  */
  public function doUpdateVirtual($path) {
    $ret = secureblackbox_archivewriter_do_updatevirtual($this->handle, $path);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_archivewriter_get($this->handle, 0);
  }
 /**
  * The type of the archive.
  *
  * @access   public
  */
  public function getArchiveType() {
    return secureblackbox_archivewriter_get($this->handle, 1 );
  }


 /**
  * The compression level to apply to the archived data.
  *
  * @access   public
  */
  public function getCompressionLevel() {
    return secureblackbox_archivewriter_get($this->handle, 2 );
  }
 /**
  * The compression level to apply to the archived data.
  *
  * @access   public
  * @param    int   value
  */
  public function setCompressionLevel($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the DecryptionCert arrays.
  *
  * @access   public
  */
  public function getDecryptionCertCount() {
    return secureblackbox_archivewriter_get($this->handle, 3 );
  }
 /**
  * The number of records in the DecryptionCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setDecryptionCertCount($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getDecryptionCertBytes($decryptioncertindex) {
    return secureblackbox_archivewriter_get($this->handle, 4 , $decryptioncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getDecryptionCertHandle($decryptioncertindex) {
    return secureblackbox_archivewriter_get($this->handle, 5 , $decryptioncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setDecryptionCertHandle($decryptioncertindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 5, $value , $decryptioncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The decryption password.
  *
  * @access   public
  */
  public function getDecryptionPassword() {
    return secureblackbox_archivewriter_get($this->handle, 6 );
  }
 /**
  * The decryption password.
  *
  * @access   public
  * @param    string   value
  */
  public function setDecryptionPassword($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the encryption algorithm to apply to the archive.
  *
  * @access   public
  */
  public function getEncryptionAlgorithm() {
    return secureblackbox_archivewriter_get($this->handle, 7 );
  }
 /**
  * Specifies the encryption algorithm to apply to the archive.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptionAlgorithm($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getEncryptionCertBytes() {
    return secureblackbox_archivewriter_get($this->handle, 8 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getEncryptionCertHandle() {
    return secureblackbox_archivewriter_get($this->handle, 9 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setEncryptionCertHandle($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the archive encryption password.
  *
  * @access   public
  */
  public function getEncryptionPassword() {
    return secureblackbox_archivewriter_get($this->handle, 10 );
  }
 /**
  * Specifies the archive encryption password.
  *
  * @access   public
  * @param    string   value
  */
  public function setEncryptionPassword($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 10, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of encryption to apply to the archive.
  *
  * @access   public
  */
  public function getEncryptionType() {
    return secureblackbox_archivewriter_get($this->handle, 11 );
  }
 /**
  * The type of encryption to apply to the archive.
  *
  * @access   public
  * @param    int   value
  */
  public function setEncryptionType($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 11, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The contents of the file being added to the archive.
  *
  * @access   public
  */
  public function getFileData() {
    return secureblackbox_archivewriter_get($this->handle, 12 );
  }
 /**
  * The contents of the file being added to the archive.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileData($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the File arrays.
  *
  * @access   public
  */
  public function getFileCount() {
    return secureblackbox_archivewriter_get($this->handle, 13 );
  }
 /**
  * The number of records in the File arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileCount($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The action to apply to the file.
  *
  * @access   public
  */
  public function getFileAction($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 14 , $fileindex);
  }
 /**
  * The action to apply to the file.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileAction($fileindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 14, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The size of the file after compression.
  *
  * @access   public
  */
  public function getFileCompressedSize($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 15 , $fileindex);
  }


 /**
  * The type of the data source for this entry.
  *
  * @access   public
  */
  public function getFileDataSource($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 16 , $fileindex);
  }
 /**
  * The type of the data source for this entry.
  *
  * @access   public
  * @param    int   value
  */
  public function setFileDataSource($fileindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 16, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Tells if the entry is a directory or a regular file.
  *
  * @access   public
  */
  public function getFileDirectory($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 17 , $fileindex);
  }


 /**
  * Returns the symmetric algorithm that was used to encrypt the file.
  *
  * @access   public
  */
  public function getFileEncryptionAlgorithm($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 18 , $fileindex);
  }


 /**
  * Returns the length, in bits, of the encryption key.
  *
  * @access   public
  */
  public function getFileEncryptionKeyLength($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 19 , $fileindex);
  }


 /**
  * The type of encryption applied to the file.
  *
  * @access   public
  */
  public function getFileEncryptionType($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 20 , $fileindex);
  }


 /**
  * The original name of the compressed file or folder.
  *
  * @access   public
  */
  public function getFileFileName($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 21 , $fileindex);
  }
 /**
  * The original name of the compressed file or folder.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileFileName($fileindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 21, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The containing folder of the entry.
  *
  * @access   public
  */
  public function getFileFolder($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 22 , $fileindex);
  }


 /**
  * The local path associated with this entry.
  *
  * @access   public
  */
  public function getFileLocalPath($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 23 , $fileindex);
  }
 /**
  * The local path associated with this entry.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileLocalPath($fileindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 23, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The entry's last modification time.
  *
  * @access   public
  */
  public function getFileMTime($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 24 , $fileindex);
  }
 /**
  * The entry's last modification time.
  *
  * @access   public
  * @param    string   value
  */
  public function setFileMTime($fileindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 24, $value , $fileindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates whether the entry corresponds to a file to be added to the archive.
  *
  * @access   public
  */
  public function getFileNewFile($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 25 , $fileindex);
  }


 /**
  * The full internal path of the archived entry.
  *
  * @access   public
  */
  public function getFilePath($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 26 , $fileindex);
  }


 /**
  * The number of signatures covering the entry.
  *
  * @access   public
  */
  public function getFileSignatureCount($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 27 , $fileindex);
  }


 /**
  * Indicates whether the entry is signed.
  *
  * @access   public
  */
  public function getFileSigned($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 28 , $fileindex);
  }


 /**
  * The size of the file before compression.
  *
  * @access   public
  */
  public function getFileSize($fileindex) {
    return secureblackbox_archivewriter_get($this->handle, 29 , $fileindex);
  }


 /**
  * Indicates whether the archive object represents a new (rather than opened) archive.
  *
  * @access   public
  */
  public function getNewArchive() {
    return secureblackbox_archivewriter_get($this->handle, 30 );
  }


 /**
  * Indicates whether class is currently in edit mode.
  *
  * @access   public
  */
  public function getOpened() {
    return secureblackbox_archivewriter_get($this->handle, 31 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_archivewriter_get($this->handle, 32 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_archivewriter_get($this->handle, 33 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningCertHandle($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 33, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  */
  public function getSigningChainCount() {
    return secureblackbox_archivewriter_get($this->handle, 34 );
  }
 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setSigningChainCount($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 34, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningChainBytes($signingchainindex) {
    return secureblackbox_archivewriter_get($this->handle, 35 , $signingchainindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningChainHandle($signingchainindex) {
    return secureblackbox_archivewriter_get($this->handle, 36 , $signingchainindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningChainHandle($signingchainindex, $value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 36, $value , $signingchainindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_archivewriter_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_archivewriter_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_archivewriter_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Marks the completion of compression of a file.
  *
  * @access   public
  * @param    array   Array of event parameters: path, filesize, datasource    
  */
  public function fireAfterCompressFile($param) {
    return $param;
  }

 /**
  * Marks the start of compression of a file.
  *
  * @access   public
  * @param    array   Array of event parameters: path, filesize, datasource    
  */
  public function fireBeforeCompressFile($param) {
    return $param;
  }

 /**
  * Fires when the class needs a password to decrypt the archive.
  *
  * @access   public
  * @param    array   Array of event parameters: passwordtarget, cancel    
  */
  public function fireDecryptionPasswordNeeded($param) {
    return $param;
  }

 /**
  * Reports information about errors during archive assembling.
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
  * Fires for every file to be compressed before the compression starts.
  *
  * @access   public
  * @param    array   Array of event parameters: path, filesize, datasource, localpath, action    
  */
  public function firePrepareFile($param) {
    return $param;
  }

 /**
  * Reports the progress of data compression.
  *
  * @access   public
  * @param    array   Array of event parameters: processed, total, overallprocessed, overalltotal, cancel    
  */
  public function fireProgress($param) {
    return $param;
  }

 /**
  * Signifies that the archive was found to be encrypted with a digital certificate.
  *
  * @access   public
  * @param    array   Array of event parameters: publickeyhash, certfound    
  */
  public function fireRecipientFound($param) {
    return $param;
  }


}

?>
