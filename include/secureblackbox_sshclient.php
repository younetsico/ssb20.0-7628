<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SSHClient Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SSHClient {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_sshclient_open(SECUREBLACKBOX_OEMKEY_917);
    secureblackbox_sshclient_register_callback($this->handle, 1, array($this, 'fireAuthAttempt'));
    secureblackbox_sshclient_register_callback($this->handle, 2, array($this, 'fireAuthFailed'));
    secureblackbox_sshclient_register_callback($this->handle, 3, array($this, 'fireAuthSucceeded'));
    secureblackbox_sshclient_register_callback($this->handle, 4, array($this, 'fireBanner'));
    secureblackbox_sshclient_register_callback($this->handle, 5, array($this, 'fireCommandCompleted'));
    secureblackbox_sshclient_register_callback($this->handle, 6, array($this, 'fireCommandStart'));
    secureblackbox_sshclient_register_callback($this->handle, 7, array($this, 'fireConnect'));
    secureblackbox_sshclient_register_callback($this->handle, 8, array($this, 'fireDataReceived'));
    secureblackbox_sshclient_register_callback($this->handle, 9, array($this, 'fireDataSent'));
    secureblackbox_sshclient_register_callback($this->handle, 10, array($this, 'fireDisconnect'));
    secureblackbox_sshclient_register_callback($this->handle, 11, array($this, 'fireError'));
    secureblackbox_sshclient_register_callback($this->handle, 12, array($this, 'fireExternalSign'));
    secureblackbox_sshclient_register_callback($this->handle, 13, array($this, 'fireKnownKeyReceived'));
    secureblackbox_sshclient_register_callback($this->handle, 14, array($this, 'fireNotification'));
    secureblackbox_sshclient_register_callback($this->handle, 15, array($this, 'firePasswordChangeRequest'));
    secureblackbox_sshclient_register_callback($this->handle, 16, array($this, 'firePrivateKeyNeeded'));
    secureblackbox_sshclient_register_callback($this->handle, 17, array($this, 'fireUnknownKeyReceived'));
  }
  
  public function __destruct() {
    secureblackbox_sshclient_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_sshclient_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_sshclient_get_last_error_code($this->handle);
  }

 /**
  * Sets or retrieves a configuration setting.
  *
  * @access   public
  * @param    string    configurationstring
  */
  public function doConfig($configurationstring) {
    $ret = secureblackbox_sshclient_do_config($this->handle, $configurationstring);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Establishes connection to an SSH server.
  *
  * @access   public
  * @param    string    address
  * @param    int    port
  */
  public function doConnect($address, $port) {
    $ret = secureblackbox_sshclient_do_connect($this->handle, $address, $port);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Connects to an SSH server and executes a command in one go.
  *
  * @access   public
  * @param    string    address
  * @param    int    port
  * @param    string    command
  * @param    boolean    wantstdout
  * @param    boolean    wantstderr
  */
  public function doConnectAndExec($address, $port, $command, $wantstdout, $wantstderr) {
    $ret = secureblackbox_sshclient_do_connectandexec($this->handle, $address, $port, $command, $wantstdout, $wantstderr);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Closes connection to the SSH server.
  *
  * @access   public
  */
  public function doDisconnect() {
    $ret = secureblackbox_sshclient_do_disconnect($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sends a keep-alive request to the SSH server.
  *
  * @access   public
  */
  public function doPing() {
    $ret = secureblackbox_sshclient_do_ping($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Checks whether there is any inbound data readily available.
  *
  * @access   public
  * @param    int    milliseconds
  */
  public function doPoll($milliseconds) {
    $ret = secureblackbox_sshclient_do_poll($this->handle, $milliseconds);
		$err = 0;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Reads a portion of received data into a string.
  *
  * @access   public
  */
  public function doReceive() {
    $ret = secureblackbox_sshclient_do_receive($this->handle);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Reads a portion of received data into a byte array.
  *
  * @access   public
  * @param    int    maxlen
  */
  public function doReceiveBytes($maxlen) {
    $ret = secureblackbox_sshclient_do_receivebytes($this->handle, $maxlen);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Reads a portion of data received via a specific channel into a byte array.
  *
  * @access   public
  * @param    int    channel
  * @param    int    maxlen
  */
  public function doReceiveBytesFrom($channel, $maxlen) {
    $ret = secureblackbox_sshclient_do_receivebytesfrom($this->handle, $channel, $maxlen);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Reads a portion of data received via a specific channel into a string.
  *
  * @access   public
  * @param    int    channel
  */
  public function doReceiveFrom($channel) {
    $ret = secureblackbox_sshclient_do_receivefrom($this->handle, $channel);
		$err = secureblackbox_sshclient_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sends a string to the server.
  *
  * @access   public
  * @param    string    datastr
  * @param    boolean    addeol
  */
  public function doSend($datastr, $addeol) {
    $ret = secureblackbox_sshclient_do_send($this->handle, $datastr, $addeol);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sends an array of bytes to the server.
  *
  * @access   public
  * @param    string    data
  */
  public function doSendBytes($data) {
    $ret = secureblackbox_sshclient_do_sendbytes($this->handle, $data);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sends a special character to the server or remote command.
  *
  * @access   public
  * @param    string    specialchar
  */
  public function doSendSpecial($specialchar) {
    $ret = secureblackbox_sshclient_do_sendspecial($this->handle, $specialchar);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_sshclient_get($this->handle, 0);
  }
 /**
  * Controls the SSH clients mode of work.
  *
  * @access   public
  */
  public function getAsyncMode() {
    return secureblackbox_sshclient_get($this->handle, 1 );
  }
 /**
  * Controls the SSH clients mode of work.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAsyncMode($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the number of SSH password authentication attempts.
  *
  * @access   public
  */
  public function getAuthAttempts() {
    return secureblackbox_sshclient_get($this->handle, 2 );
  }
 /**
  * Specifies the number of SSH password authentication attempts.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthAttempts($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the list of commands to execute.
  *
  * @access   public
  */
  public function getCommands() {
    return secureblackbox_sshclient_get($this->handle, 3 );
  }
 /**
  * Specifies the list of commands to execute.
  *
  * @access   public
  * @param    string   value
  */
  public function setCommands($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the client is connected to the SFTP server.
  *
  * @access   public
  */
  public function getConnected() {
    return secureblackbox_sshclient_get($this->handle, 4 );
  }


 /**
  * Specifies the client's key algorithm.
  *
  * @access   public
  */
  public function getConnInfoClientKeyAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 5 );
  }


 /**
  * Specifies the length of the client's key.
  *
  * @access   public
  */
  public function getConnInfoClientKeyBits() {
    return secureblackbox_sshclient_get($this->handle, 6 );
  }


 /**
  * The fingerprint (hash value) of the client's public key.
  *
  * @access   public
  */
  public function getConnInfoClientKeyFingerprint() {
    return secureblackbox_sshclient_get($this->handle, 7 );
  }


 /**
  * Contains the line sent by the server just before closing the connection.
  *
  * @access   public
  */
  public function getConnInfoCloseReason() {
    return secureblackbox_sshclient_get($this->handle, 8 );
  }


 /**
  * Compression algorithm for the incoming traffic.
  *
  * @access   public
  */
  public function getConnInfoCompressionAlgorithmInbound() {
    return secureblackbox_sshclient_get($this->handle, 9 );
  }


 /**
  * Compression algorithm for the outgoing traffic.
  *
  * @access   public
  */
  public function getConnInfoCompressionAlgorithmOutbound() {
    return secureblackbox_sshclient_get($this->handle, 10 );
  }


 /**
  * Encryption algorithm for the incoming traffic.
  *
  * @access   public
  */
  public function getConnInfoEncryptionAlgorithmInbound() {
    return secureblackbox_sshclient_get($this->handle, 11 );
  }


 /**
  * Encryption algorithm for the outgoing traffic.
  *
  * @access   public
  */
  public function getConnInfoEncryptionAlgorithmOutbound() {
    return secureblackbox_sshclient_get($this->handle, 12 );
  }


 /**
  * Specifies the length of the key used to encrypt the incoming traffic.
  *
  * @access   public
  */
  public function getConnInfoInboundEncryptionKeyBits() {
    return secureblackbox_sshclient_get($this->handle, 13 );
  }


 /**
  * The key exchange algorithm used during the SSH handshake.
  *
  * @access   public
  */
  public function getConnInfoKexAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 14 );
  }


 /**
  * The number of bits used by the key exchange algorithm.
  *
  * @access   public
  */
  public function getConnInfoKexBits() {
    return secureblackbox_sshclient_get($this->handle, 15 );
  }


 /**
  * The contents of the received KexInit packet.
  *
  * @access   public
  */
  public function getConnInfoKexLines() {
    return secureblackbox_sshclient_get($this->handle, 16 );
  }


 /**
  * MAC algorithm used for the incoming connection.
  *
  * @access   public
  */
  public function getConnInfoMacAlgorithmInbound() {
    return secureblackbox_sshclient_get($this->handle, 17 );
  }


 /**
  * MAC algorithm used for outbound connection.
  *
  * @access   public
  */
  public function getConnInfoMacAlgorithmOutbound() {
    return secureblackbox_sshclient_get($this->handle, 18 );
  }


 /**
  * Specifies the length of the key used to encrypt the outgoing traffic.
  *
  * @access   public
  */
  public function getConnInfoOutboundEncryptionKeyBits() {
    return secureblackbox_sshclient_get($this->handle, 19 );
  }


 /**
  * Specifies the public key algorithm which was used during the SSH handshake.
  *
  * @access   public
  */
  public function getConnInfoPublicKeyAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 20 );
  }


 /**
  * Specifies the number of bits in the server's key.
  *
  * @access   public
  */
  public function getConnInfoServerKeyBits() {
    return secureblackbox_sshclient_get($this->handle, 21 );
  }


 /**
  * The fingerprint (hash value) of the server's public key.
  *
  * @access   public
  */
  public function getConnInfoServerKeyFingerprint() {
    return secureblackbox_sshclient_get($this->handle, 22 );
  }


 /**
  * Returns the name of the SSH software running on the server side.
  *
  * @access   public
  */
  public function getConnInfoServerSoftwareName() {
    return secureblackbox_sshclient_get($this->handle, 23 );
  }


 /**
  * Returns the total number of bytes received over this connection.
  *
  * @access   public
  */
  public function getConnInfoTotalBytesReceived() {
    return secureblackbox_sshclient_get($this->handle, 24 );
  }


 /**
  * Returns the total number of bytes sent over this connection.
  *
  * @access   public
  */
  public function getConnInfoTotalBytesSent() {
    return secureblackbox_sshclient_get($this->handle, 25 );
  }


 /**
  * Specifies SSH protocol version.
  *
  * @access   public
  */
  public function getConnInfoVersion() {
    return secureblackbox_sshclient_get($this->handle, 26 );
  }


 /**
  * Contains the last commands exit message.
  *
  * @access   public
  */
  public function getExitMessage() {
    return secureblackbox_sshclient_get($this->handle, 27 );
  }


 /**
  * Contains the last commands exit signal.
  *
  * @access   public
  */
  public function getExitSignal() {
    return secureblackbox_sshclient_get($this->handle, 28 );
  }


 /**
  * Contains the last commands exit status.
  *
  * @access   public
  */
  public function getExitStatus() {
    return secureblackbox_sshclient_get($this->handle, 29 );
  }


 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  */
  public function getExternalCryptoCustomParams() {
    return secureblackbox_sshclient_get($this->handle, 30 );
  }
 /**
  * Custom parameters to be passed to the signing service (uninterpreted).
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoCustomParams($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  */
  public function getExternalCryptoData() {
    return secureblackbox_sshclient_get($this->handle, 31 );
  }
 /**
  * Additional data to be included in the async state and mirrored back by the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoData($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 31, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  */
  public function getExternalCryptoExternalHashCalculation() {
    return secureblackbox_sshclient_get($this->handle, 32 );
  }
 /**
  * Specifies whether the message hash is to be calculated at the external endpoint.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setExternalCryptoExternalHashCalculation($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  */
  public function getExternalCryptoHashAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 33 );
  }
 /**
  * Specifies the request's signature hash algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoHashAlgorithm($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 33, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeyID() {
    return secureblackbox_sshclient_get($this->handle, 34 );
  }
 /**
  * The ID of the pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeyID($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 34, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  */
  public function getExternalCryptoKeySecret() {
    return secureblackbox_sshclient_get($this->handle, 35 );
  }
 /**
  * The pre-shared key used for DC request authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoKeySecret($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  */
  public function getExternalCryptoMethod() {
    return secureblackbox_sshclient_get($this->handle, 36 );
  }
 /**
  * Specifies the asynchronous signing method.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMethod($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  */
  public function getExternalCryptoMode() {
    return secureblackbox_sshclient_get($this->handle, 37 );
  }
 /**
  * Specifies the external cryptography mode.
  *
  * @access   public
  * @param    int   value
  */
  public function setExternalCryptoMode($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  */
  public function getExternalCryptoPublicKeyAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 38 );
  }
 /**
  * Provide public key algorithm here if the certificate is not available on the pre-signing stage.
  *
  * @access   public
  * @param    string   value
  */
  public function setExternalCryptoPublicKeyAlgorithm($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 38, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the SHA-1 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getKeyFingerprintSHA1() {
    return secureblackbox_sshclient_get($this->handle, 39 );
  }


 /**
  * Contains the SHA-256 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getKeyFingerprintSHA256() {
    return secureblackbox_sshclient_get($this->handle, 40 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKeyHandle() {
    return secureblackbox_sshclient_get($this->handle, 41 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKeyHandle($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 41, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies user's password on the server.
  *
  * @access   public
  */
  public function getPassword() {
    return secureblackbox_sshclient_get($this->handle, 42 );
  }
 /**
  * Specifies user's password on the server.
  *
  * @access   public
  * @param    string   value
  */
  public function setPassword($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 42, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxySettingsAddress() {
    return secureblackbox_sshclient_get($this->handle, 43 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsAddress($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 43, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxySettingsAuthentication() {
    return secureblackbox_sshclient_get($this->handle, 44 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxySettingsAuthentication($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 44, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxySettingsPassword() {
    return secureblackbox_sshclient_get($this->handle, 45 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsPassword($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 45, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxySettingsPort() {
    return secureblackbox_sshclient_get($this->handle, 46 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxySettingsPort($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 46, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxySettingsProxyType() {
    return secureblackbox_sshclient_get($this->handle, 47 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxySettingsProxyType($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 47, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxySettingsRequestHeaders() {
    return secureblackbox_sshclient_get($this->handle, 48 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsRequestHeaders($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 48, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxySettingsResponseBody() {
    return secureblackbox_sshclient_get($this->handle, 49 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsResponseBody($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 49, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxySettingsResponseHeaders() {
    return secureblackbox_sshclient_get($this->handle, 50 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsResponseHeaders($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 50, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxySettingsUseIPv6() {
    return secureblackbox_sshclient_get($this->handle, 51 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxySettingsUseIPv6($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 51, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxySettingsUseProxy() {
    return secureblackbox_sshclient_get($this->handle, 52 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxySettingsUseProxy($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 52, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxySettingsUsername() {
    return secureblackbox_sshclient_get($this->handle, 53 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxySettingsUsername($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 53, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the key algorithm.
  *
  * @access   public
  */
  public function getServerKeyAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 54 );
  }


 /**
  * The number of bits in the key: the more the better, 2048 or 4096 are typical values.
  *
  * @access   public
  */
  public function getServerKeyBits() {
    return secureblackbox_sshclient_get($this->handle, 55 );
  }


 /**
  * The comment for the public key.
  *
  * @access   public
  */
  public function getServerKeyComment() {
    return secureblackbox_sshclient_get($this->handle, 56 );
  }


 /**
  * Specifies the elliptical curve when EC cryptography is used.
  *
  * @access   public
  */
  public function getServerKeyCurve() {
    return secureblackbox_sshclient_get($this->handle, 57 );
  }


 /**
  * The G (Generator) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getServerKeyDSSG() {
    return secureblackbox_sshclient_get($this->handle, 58 );
  }


 /**
  * The P (Prime) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getServerKeyDSSP() {
    return secureblackbox_sshclient_get($this->handle, 59 );
  }


 /**
  * The Q (Prime Factor) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getServerKeyDSSQ() {
    return secureblackbox_sshclient_get($this->handle, 60 );
  }


 /**
  * The X (Private key) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getServerKeyDSSX() {
    return secureblackbox_sshclient_get($this->handle, 61 );
  }


 /**
  * The Y (Public key) parameter of the DSS signature key.
  *
  * @access   public
  */
  public function getServerKeyDSSY() {
    return secureblackbox_sshclient_get($this->handle, 62 );
  }


 /**
  * The value of the secret key (the order of the public key, D) if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getServerKeyECCD() {
    return secureblackbox_sshclient_get($this->handle, 63 );
  }


 /**
  * The value of the X coordinate of the public key if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getServerKeyECCQX() {
    return secureblackbox_sshclient_get($this->handle, 64 );
  }


 /**
  * The value of the Y coordinate of the public key if elliptic curve (EC) cryptography is used.
  *
  * @access   public
  */
  public function getServerKeyECCQY() {
    return secureblackbox_sshclient_get($this->handle, 65 );
  }


 /**
  * The value of the private key if EdDSA (Edwards-curve Digital Signature Algorithm) algorithm is used.
  *
  * @access   public
  */
  public function getServerKeyEdPrivate() {
    return secureblackbox_sshclient_get($this->handle, 66 );
  }


 /**
  * The value of the public key if EdDSA (Edwards-curve Digital Signature Algorithm) algorithm is used.
  *
  * @access   public
  */
  public function getServerKeyEdPublic() {
    return secureblackbox_sshclient_get($this->handle, 67 );
  }


 /**
  * Contains the MD5 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getServerKeyFingerprintMD5() {
    return secureblackbox_sshclient_get($this->handle, 68 );
  }


 /**
  * Contains the SHA-1 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getServerKeyFingerprintSHA1() {
    return secureblackbox_sshclient_get($this->handle, 69 );
  }


 /**
  * Contains the SHA-256 fingerprint (hash) of the key.
  *
  * @access   public
  */
  public function getServerKeyFingerprintSHA256() {
    return secureblackbox_sshclient_get($this->handle, 70 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getServerKeyHandle() {
    return secureblackbox_sshclient_get($this->handle, 71 );
  }


 /**
  * Whether the key is extractable (e.
  *
  * @access   public
  */
  public function getServerKeyIsExtractable() {
    return secureblackbox_sshclient_get($this->handle, 72 );
  }


 /**
  * Whether this key is a private key or not.
  *
  * @access   public
  */
  public function getServerKeyIsPrivate() {
    return secureblackbox_sshclient_get($this->handle, 73 );
  }


 /**
  * Whether this key is a public key or not.
  *
  * @access   public
  */
  public function getServerKeyIsPublic() {
    return secureblackbox_sshclient_get($this->handle, 74 );
  }


 /**
  * Returns the number of iterations of the Key Derivation Function (KDF) used to generate this key.
  *
  * @access   public
  */
  public function getServerKeyKDFRounds() {
    return secureblackbox_sshclient_get($this->handle, 75 );
  }


 /**
  * The salt value used by the Key Derivation Function (KDF) to generate this key.
  *
  * @access   public
  */
  public function getServerKeyKDFSalt() {
    return secureblackbox_sshclient_get($this->handle, 76 );
  }


 /**
  * Specifies the format in which the key is stored.
  *
  * @access   public
  */
  public function getServerKeyKeyFormat() {
    return secureblackbox_sshclient_get($this->handle, 77 );
  }


 /**
  * Specifies the key protection algorithm.
  *
  * @access   public
  */
  public function getServerKeyKeyProtectionAlgorithm() {
    return secureblackbox_sshclient_get($this->handle, 78 );
  }


 /**
  * Returns the e parameter (public exponent) of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAExponent() {
    return secureblackbox_sshclient_get($this->handle, 79 );
  }


 /**
  * Returns the iqmp parameter of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAIQMP() {
    return secureblackbox_sshclient_get($this->handle, 80 );
  }


 /**
  * Returns the m parameter (public modulus) of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAModulus() {
    return secureblackbox_sshclient_get($this->handle, 81 );
  }


 /**
  * Returns the p parameter (first factor of the common modulus n) of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAP() {
    return secureblackbox_sshclient_get($this->handle, 82 );
  }


 /**
  * Returns the d parameter (private exponent) of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAPrivateExponent() {
    return secureblackbox_sshclient_get($this->handle, 83 );
  }


 /**
  * Returns the q parameter (second factor of the common modulus n) of the RSA key.
  *
  * @access   public
  */
  public function getServerKeyRSAQ() {
    return secureblackbox_sshclient_get($this->handle, 84 );
  }


 /**
  * Specifies the public key owner (subject).
  *
  * @access   public
  */
  public function getServerKeySubject() {
    return secureblackbox_sshclient_get($this->handle, 85 );
  }


 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_sshclient_get($this->handle, 86 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_sshclient_get($this->handle, 87 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 87, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_sshclient_get($this->handle, 88 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 88, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_sshclient_get($this->handle, 89 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 89, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_sshclient_get($this->handle, 90 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_sshclient_get($this->handle, 91 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 91, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_sshclient_get($this->handle, 92 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 92, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_sshclient_get($this->handle, 93 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 93, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_sshclient_get($this->handle, 94 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 94, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_sshclient_get($this->handle, 95 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 95, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_sshclient_get($this->handle, 96 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 96, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether the SSH client should adjust its list of supported ciphers 'on-the-fly' for greater compatibility with the server it is connecting to.
  *
  * @access   public
  */
  public function getSSHSettingsAutoAdjustCiphers() {
    return secureblackbox_sshclient_get($this->handle, 97 );
  }
 /**
  * Whether the SSH client should adjust its list of supported ciphers 'on-the-fly' for greater compatibility with the server it is connecting to.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsAutoAdjustCiphers($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 97, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Allows to choose base configuration of SSH settings, tuned up for different purposes such as high security or higher compatibility.
  *
  * @access   public
  */
  public function getSSHSettingsBaseConfiguration() {
    return secureblackbox_sshclient_get($this->handle, 98 );
  }
 /**
  * Allows to choose base configuration of SSH settings, tuned up for different purposes such as high security or higher compatibility.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsBaseConfiguration($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 98, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the algorithms which can be used  to compress data during the SSH session.
  *
  * @access   public
  */
  public function getSSHSettingsCompressionAlgorithms() {
    return secureblackbox_sshclient_get($this->handle, 99 );
  }
 /**
  * Specifies the algorithms which can be used  to compress data during the SSH session.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsCompressionAlgorithms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 99, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Possible values for the Compression Level range from 0 (minimum compression)  to 9 (maximum compression).
  *
  * @access   public
  */
  public function getSSHSettingsCompressionLevel() {
    return secureblackbox_sshclient_get($this->handle, 100 );
  }
 /**
  * Possible values for the Compression Level range from 0 (minimum compression)  to 9 (maximum compression).
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsCompressionLevel($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 100, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The SSH window size specifies how many bytes the client  can send to the server in the command channel.
  *
  * @access   public
  */
  public function getSSHSettingsDefaultWindowSize() {
    return secureblackbox_sshclient_get($this->handle, 101 );
  }
 /**
  * The SSH window size specifies how many bytes the client  can send to the server in the command channel.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsDefaultWindowSize($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 101, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the encryption algorithms which can be used during SSH connection.
  *
  * @access   public
  */
  public function getSSHSettingsEncryptionAlgorithms() {
    return secureblackbox_sshclient_get($this->handle, 102 );
  }
 /**
  * Specifies the encryption algorithms which can be used during SSH connection.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsEncryptionAlgorithms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 102, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether the SSH client should explicitly request compression.
  *
  * @access   public
  */
  public function getSSHSettingsForceCompression() {
    return secureblackbox_sshclient_get($this->handle, 103 );
  }
 /**
  * Whether the SSH client should explicitly request compression.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsForceCompression($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 103, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A comma-separated list of authentication types.
  *
  * @access   public
  */
  public function getSSHSettingsGSSAuthTypes() {
    return secureblackbox_sshclient_get($this->handle, 104 );
  }
 /**
  * A comma-separated list of authentication types.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsGSSAuthTypes($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 104, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Switches credential delegation on or off.
  *
  * @access   public
  */
  public function getSSHSettingsGSSDelegateCreds() {
    return secureblackbox_sshclient_get($this->handle, 105 );
  }
 /**
  * Switches credential delegation on or off.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsGSSDelegateCreds($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 105, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The GSS host name, in form of a FQDN (e.
  *
  * @access   public
  */
  public function getSSHSettingsGSSHostname() {
    return secureblackbox_sshclient_get($this->handle, 106 );
  }
 /**
  * The GSS host name, in form of a FQDN (e.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsGSSHostname($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 106, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A path to the GSS-API library (DLL or SO).
  *
  * @access   public
  */
  public function getSSHSettingsGSSLib() {
    return secureblackbox_sshclient_get($this->handle, 107 );
  }
 /**
  * A path to the GSS-API library (DLL or SO).
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsGSSLib($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 107, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A comma-separated list of GSS mechanisms to use.
  *
  * @access   public
  */
  public function getSSHSettingsGSSMechanisms() {
    return secureblackbox_sshclient_get($this->handle, 108 );
  }
 /**
  * A comma-separated list of GSS mechanisms to use.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsGSSMechanisms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 108, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A comma-separated list of SSPI protocols.
  *
  * @access   public
  */
  public function getSSHSettingsGSSProtocols() {
    return secureblackbox_sshclient_get($this->handle, 109 );
  }
 /**
  * A comma-separated list of SSPI protocols.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsGSSProtocols($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 109, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the maximal time for the SSH handshake to proceed, in seconds.
  *
  * @access   public
  */
  public function getSSHSettingsHandshakeTimeout() {
    return secureblackbox_sshclient_get($this->handle, 110 );
  }
 /**
  * Specifies the maximal time for the SSH handshake to proceed, in seconds.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsHandshakeTimeout($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 110, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the key exchange algorithms which can be used to  establish the secure session.
  *
  * @access   public
  */
  public function getSSHSettingsKexAlgorithms() {
    return secureblackbox_sshclient_get($this->handle, 111 );
  }
 /**
  * Specifies the key exchange algorithms which can be used to  establish the secure session.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsKexAlgorithms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 111, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the MAC (message authentication code) algorithms  which may be used through the SSH session.
  *
  * @access   public
  */
  public function getSSHSettingsMacAlgorithms() {
    return secureblackbox_sshclient_get($this->handle, 112 );
  }
 /**
  * Specifies the MAC (message authentication code) algorithms  which may be used through the SSH session.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsMacAlgorithms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 112, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the maximum length of one SSH packet in bytes.
  *
  * @access   public
  */
  public function getSSHSettingsMaxSSHPacketSize() {
    return secureblackbox_sshclient_get($this->handle, 113 );
  }
 /**
  * Specifies the maximum length of one SSH packet in bytes.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsMaxSSHPacketSize($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 113, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the minimal internal window size.
  *
  * @access   public
  */
  public function getSSHSettingsMinWindowSize() {
    return secureblackbox_sshclient_get($this->handle, 114 );
  }
 /**
  * Specifies the minimal internal window size.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsMinWindowSize($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 114, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether handshake obfuscation is used.
  *
  * @access   public
  */
  public function getSSHSettingsObfuscateHandshake() {
    return secureblackbox_sshclient_get($this->handle, 115 );
  }
 /**
  * Specifies whether handshake obfuscation is used.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsObfuscateHandshake($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 115, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the password used to encrypt the handshake when ObfuscateHandshake is set.
  *
  * @access   public
  */
  public function getSSHSettingsObfuscationPassword() {
    return secureblackbox_sshclient_get($this->handle, 116 );
  }
 /**
  * Specifies the password used to encrypt the handshake when ObfuscateHandshake is set.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsObfuscationPassword($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 116, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the public key algorithms that can be used during the SSH handshake.
  *
  * @access   public
  */
  public function getSSHSettingsPublicKeyAlgorithms() {
    return secureblackbox_sshclient_get($this->handle, 117 );
  }
 /**
  * Specifies the public key algorithms that can be used during the SSH handshake.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsPublicKeyAlgorithms($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 117, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether the user needs to change the password.
  *
  * @access   public
  */
  public function getSSHSettingsRequestPasswordChange() {
    return secureblackbox_sshclient_get($this->handle, 118 );
  }
 /**
  * Whether the user needs to change the password.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsRequestPasswordChange($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 118, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The name of the SSH software running on this server.
  *
  * @access   public
  */
  public function getSSHSettingsSoftwareName() {
    return secureblackbox_sshclient_get($this->handle, 119 );
  }
 /**
  * The name of the SSH software running on this server.
  *
  * @access   public
  * @param    string   value
  */
  public function setSSHSettingsSoftwareName($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 119, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables explicit trust to all server keys.
  *
  * @access   public
  */
  public function getSSHSettingsTrustAllKeys() {
    return secureblackbox_sshclient_get($this->handle, 120 );
  }
 /**
  * Enables or disables explicit trust to all server keys.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsTrustAllKeys($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 120, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables the use of external key agent, such as Putty key agent.
  *
  * @access   public
  */
  public function getSSHSettingsUseAuthAgent() {
    return secureblackbox_sshclient_get($this->handle, 121 );
  }
 /**
  * Enables or disables the use of external key agent, such as Putty key agent.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSSHSettingsUseAuthAgent($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 121, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies supported SSH protocol versions.
  *
  * @access   public
  */
  public function getSSHSettingsVersions() {
    return secureblackbox_sshclient_get($this->handle, 122 );
  }
 /**
  * Specifies supported SSH protocol versions.
  *
  * @access   public
  * @param    int   value
  */
  public function setSSHSettingsVersions($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 122, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the subsystem to request from the server.
  *
  * @access   public
  */
  public function getSubsystem() {
    return secureblackbox_sshclient_get($this->handle, 123 );
  }
 /**
  * Specifies the subsystem to request from the server.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubsystem($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 123, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the width of the pseudoterminal, in characters.
  *
  * @access   public
  */
  public function getTerminalCols() {
    return secureblackbox_sshclient_get($this->handle, 124 );
  }
 /**
  * Specifies the width of the pseudoterminal, in characters.
  *
  * @access   public
  * @param    int   value
  */
  public function setTerminalCols($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 124, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the list of environment variables.
  *
  * @access   public
  */
  public function getTerminalEnvironment() {
    return secureblackbox_sshclient_get($this->handle, 125 );
  }
 /**
  * Specifies the list of environment variables.
  *
  * @access   public
  * @param    string   value
  */
  public function setTerminalEnvironment($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 125, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the End-of-Line character or sequence.
  *
  * @access   public
  */
  public function getTerminalEOLChar() {
    return secureblackbox_sshclient_get($this->handle, 126 );
  }
 /**
  * Specifies the End-of-Line character or sequence.
  *
  * @access   public
  * @param    string   value
  */
  public function setTerminalEOLChar($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 126, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the height of the pseudoterminal, in pixels.
  *
  * @access   public
  */
  public function getTerminalHeight() {
    return secureblackbox_sshclient_get($this->handle, 127 );
  }
 /**
  * Specifies the height of the pseudoterminal, in pixels.
  *
  * @access   public
  * @param    int   value
  */
  public function setTerminalHeight($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 127, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the operation codes specific for the terminal.
  *
  * @access   public
  */
  public function getTerminalOpcodes() {
    return secureblackbox_sshclient_get($this->handle, 128 );
  }
 /**
  * Specifies the operation codes specific for the terminal.
  *
  * @access   public
  * @param    string   value
  */
  public function setTerminalOpcodes($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 128, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The terminal protocol name.
  *
  * @access   public
  */
  public function getTerminalProtocol() {
    return secureblackbox_sshclient_get($this->handle, 129 );
  }
 /**
  * The terminal protocol name.
  *
  * @access   public
  * @param    string   value
  */
  public function setTerminalProtocol($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 129, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to request a pseudoterminal for the session.
  *
  * @access   public
  */
  public function getTerminalRequestPty() {
    return secureblackbox_sshclient_get($this->handle, 130 );
  }
 /**
  * Specifies whether to request a pseudoterminal for the session.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTerminalRequestPty($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 130, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the height of the pseudoterminal, in lines.
  *
  * @access   public
  */
  public function getTerminalRows() {
    return secureblackbox_sshclient_get($this->handle, 131 );
  }
 /**
  * Specifies the height of the pseudoterminal, in lines.
  *
  * @access   public
  * @param    int   value
  */
  public function setTerminalRows($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 131, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the width of the pseudoterminal, in pixels.
  *
  * @access   public
  */
  public function getTerminalWidth() {
    return secureblackbox_sshclient_get($this->handle, 132 );
  }
 /**
  * Specifies the width of the pseudoterminal, in pixels.
  *
  * @access   public
  * @param    int   value
  */
  public function setTerminalWidth($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 132, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Path to the file containing public keys of authorized servers.
  *
  * @access   public
  */
  public function getTrustedKeysFile() {
    return secureblackbox_sshclient_get($this->handle, 133 );
  }
 /**
  * Path to the file containing public keys of authorized servers.
  *
  * @access   public
  * @param    string   value
  */
  public function setTrustedKeysFile($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 133, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies client's username on the server.
  *
  * @access   public
  */
  public function getUsername() {
    return secureblackbox_sshclient_get($this->handle, 134 );
  }
 /**
  * Specifies client's username on the server.
  *
  * @access   public
  * @param    string   value
  */
  public function setUsername($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 134, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_sshclient_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_sshclient_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_sshclient_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Fires when a single authentication attempt is performed.
  *
  * @access   public
  * @param    array   Array of event parameters: authtype    
  */
  public function fireAuthAttempt($param) {
    return $param;
  }

 /**
  * Fires when a single authentication attempt is failed.
  *
  * @access   public
  * @param    array   Array of event parameters: authenticationtype    
  */
  public function fireAuthFailed($param) {
    return $param;
  }

 /**
  * Reports a successful authentication.
  *
  * @access   public
  * @param    array   Array of event parameters:     
  */
  public function fireAuthSucceeded($param) {
    return $param;
  }

 /**
  * Reports the receipt of the Hello message from the server.
  *
  * @access   public
  * @param    array   Array of event parameters: text, language    
  */
  public function fireBanner($param) {
    return $param;
  }

 /**
  * Signifies completion of the command execution.
  *
  * @access   public
  * @param    array   Array of event parameters: command, exitstatus, exitmessage, exitsignal    
  */
  public function fireCommandCompleted($param) {
    return $param;
  }

 /**
  * Marks the commencement of a command execution.
  *
  * @access   public
  * @param    array   Array of event parameters: command    
  */
  public function fireCommandStart($param) {
    return $param;
  }

 /**
  * This event is fired when an SSH session has been established.
  *
  * @access   public
  * @param    array   Array of event parameters:     
  */
  public function fireConnect($param) {
    return $param;
  }

 /**
  * Reports receipt of another chunk of data from the server.
  *
  * @access   public
  * @param    array   Array of event parameters: channel, bytesreceived, totalbytespending    
  */
  public function fireDataReceived($param) {
    return $param;
  }

 /**
  * Notifies the application that a piece of data has been sent to the server.
  *
  * @access   public
  * @param    array   Array of event parameters: bytessent, bytespending    
  */
  public function fireDataSent($param) {
    return $param;
  }

 /**
  * This event is fired when the SFTP subsystem connection is closed.
  *
  * @access   public
  * @param    array   Array of event parameters: closereason    
  */
  public function fireDisconnect($param) {
    return $param;
  }

 /**
  * Information about errors during SFTP connection.
  *
  * @access   public
  * @param    array   Array of event parameters: errorcode, description    
  */
  public function fireError($param) {
    return $param;
  }

 /**
  * Handles remote or external signing initiated by the SignExternal method or other source.
  *
  * @access   public
  * @param    array   Array of event parameters: operationid, hashalgorithm, pars, data, signeddata    
  */
  public function fireExternalSign($param) {
    return $param;
  }

 /**
  * This event is fired when a known SSH key is received from the server.
  *
  * @access   public
  * @param    array   Array of event parameters: algorithm, bits, fingerprintsha256    
  */
  public function fireKnownKeyReceived($param) {
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
  * This event is fired when a password change is requested.
  *
  * @access   public
  * @param    array   Array of event parameters: prompt, newpassword, cancel    
  */
  public function firePasswordChangeRequest($param) {
    return $param;
  }

 /**
  * This event is fired when client's public key was accepted by the  server, but the corresponding secret key is not available.
  *
  * @access   public
  * @param    array   Array of event parameters: skip    
  */
  public function firePrivateKeyNeeded($param) {
    return $param;
  }

 /**
  * This event is fired when an unknown SSH key is received from the server.
  *
  * @access   public
  * @param    array   Array of event parameters: algorithm, bits, fingerprintsha256, action    
  */
  public function fireUnknownKeyReceived($param) {
    return $param;
  }


}

?>
