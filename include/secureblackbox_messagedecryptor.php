<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - MessageDecryptor Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_MessageDecryptor {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_messagedecryptor_open(SECUREBLACKBOX_OEMKEY_280);
    secureblackbox_messagedecryptor_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_messagedecryptor_register_callback($this->handle, 2, array($this, 'fireExternalDecrypt'));
    secureblackbox_messagedecryptor_register_callback($this->handle, 3, array($this, 'fireNotification'));
    secureblackbox_messagedecryptor_register_callback($this->handle, 4, array($this, 'fireRecipientFound'));
  }
  
  public function __destruct() {
    secureblackbox_messagedecryptor_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_messagedecryptor_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_messagedecryptor_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_messagedecryptor_do_config($this->handle, $configurationstring);
		$err = secureblackbox_messagedecryptor_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Attempts to decrypt an encrypted PKCS#7 message.
  *
  * @access   public
  */
  public function doDecrypt() {
    $ret = secureblackbox_messagedecryptor_do_decrypt($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_messagedecryptor_get($this->handle, 0);
  }
 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertificateBytes() {
    return secureblackbox_messagedecryptor_get($this->handle, 1 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertificateHandle() {
    return secureblackbox_messagedecryptor_get($this->handle, 2 );
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getCertificateIssuer() {
    return secureblackbox_messagedecryptor_get($this->handle, 3 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getCertificateIssuerRDN() {
    return secureblackbox_messagedecryptor_get($this->handle, 4 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getCertificateSerialNumber() {
    return secureblackbox_messagedecryptor_get($this->handle, 5 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getCertificateSubject() {
    return secureblackbox_messagedecryptor_get($this->handle, 6 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getCertificateSubjectRDN() {
    return secureblackbox_messagedecryptor_get($this->handle, 7 );
  }


 /**
  * The number of records in the Cert arrays.
  *
  * @access   public
  */
  public function getCertCount() {
    return secureblackbox_messagedecryptor_get($this->handle, 8 );
  }
 /**
  * The number of records in the Cert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setCertCount($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getCertBytes($certindex) {
    return secureblackbox_messagedecryptor_get($this->handle, 9 , $certindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getCertHandle($certindex) {
    return secureblackbox_messagedecryptor_get($this->handle, 10 , $certindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setCertHandle($certindex, $value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 10, $value , $certindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The symmetric cipher that was used to encrypt the data.
  *
  * @access   public
  */
  public function getEncryptionAlgorithm() {
    return secureblackbox_messagedecryptor_get($this->handle, 11 );
  }


 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_messagedecryptor_get($this->handle, 12 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 12, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_messagedecryptor_get($this->handle, 13 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 13, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_messagedecryptor_get($this->handle, 14 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 14, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_messagedecryptor_get($this->handle, 15 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_messagedecryptor_get($this->handle, 16 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 16, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_messagedecryptor_get($this->handle, 17 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 17, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_messagedecryptor_get($this->handle, 18 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 18, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_messagedecryptor_get($this->handle, 19 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 19, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_messagedecryptor_get($this->handle, 20 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  */
  public function getInputBytes() {
    return secureblackbox_messagedecryptor_get($this->handle, 21 );
  }
 /**
  * Use this property to pass the input to class in the byte array form.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputBytes($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Path to the file containing the encrypted message.
  *
  * @access   public
  */
  public function getInputFile() {
    return secureblackbox_messagedecryptor_get($this->handle, 22 );
  }
 /**
  * Path to the file containing the encrypted message.
  *
  * @access   public
  * @param    string   value
  */
  public function setInputFile($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The symmetric key to use for decryption.
  *
  * @access   public
  */
  public function getKey() {
    return secureblackbox_messagedecryptor_get($this->handle, 23 );
  }
 /**
  * The symmetric key to use for decryption.
  *
  * @access   public
  * @param    string   value
  */
  public function setKey($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 23, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Use this property to read the output the class object has produced.
  *
  * @access   public
  */
  public function getOutputBytes() {
    return secureblackbox_messagedecryptor_get($this->handle, 24 );
  }


 /**
  * Path to the file to save the decrypted data to.
  *
  * @access   public
  */
  public function getOutputFile() {
    return secureblackbox_messagedecryptor_get($this->handle, 25 );
  }
 /**
  * Path to the file to save the decrypted data to.
  *
  * @access   public
  * @param    string   value
  */
  public function setOutputFile($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_messagedecryptor_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_messagedecryptor_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_messagedecryptor_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Information about errors during PKCS#7 message decryption.
  *
  * @access   public
  * @param    array   Array of event parameters: errorcode, description    
  */
  public function fireError($param) {
    return $param;
  }

 /**
  * Handles remote or external decryption.
  *
  * @access   public
  * @param    array   Array of event parameters: operationid, algorithm, pars, encrypteddata, data    
  */
  public function fireExternalDecrypt($param) {
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
  * Fires to report a message addressee parameters.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, certfound    
  */
  public function fireRecipientFound($param) {
    return $param;
  }


}

?>
