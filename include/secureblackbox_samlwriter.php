<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SAMLWriter Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SAMLWriter {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_samlwriter_open(SECUREBLACKBOX_OEMKEY_788);
    secureblackbox_samlwriter_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_samlwriter_register_callback($this->handle, 2, array($this, 'fireNotification'));
  }
  
  public function __destruct() {
    secureblackbox_samlwriter_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_samlwriter_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_samlwriter_get_last_error_code($this->handle);
  }

 /**
  * Adds an advice assertion to the message.
  *
  * @access   public
  * @param    int    assertionindex
  */
  public function doAddAdviceAssertion($assertionindex) {
    $ret = secureblackbox_samlwriter_do_addadviceassertion($this->handle, $assertionindex);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Adds assertion to a SAML message.
  *
  * @access   public
  */
  public function doAddAssertion() {
    $ret = secureblackbox_samlwriter_do_addassertion($this->handle);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Resets the contents of all assertion-related properties.
  *
  * @access   public
  */
  public function doClearAssertion() {
    $ret = secureblackbox_samlwriter_do_clearassertion($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Compares two SAML IDs.
  *
  * @access   public
  * @param    string    id1
  * @param    string    id2
  */
  public function doCompareIDs($id1, $id2) {
    $ret = secureblackbox_samlwriter_do_compareids($this->handle, $id1, $id2);
		$err = 0;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
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
    $ret = secureblackbox_samlwriter_do_config($this->handle, $configurationstring);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Creates a new SAML message with the given type.
  *
  * @access   public
  * @param    int    outputtype
  */
  public function doCreateNew($outputtype) {
    $ret = secureblackbox_samlwriter_do_createnew($this->handle, $outputtype);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns an element of the SAML ID.
  *
  * @access   public
  * @param    string    id
  * @param    string    propname
  */
  public function doGetIDProp($id, $propname) {
    $ret = secureblackbox_samlwriter_do_getidprop($this->handle, $id, $propname);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes an advice from an assertion.
  *
  * @access   public
  * @param    int    assertionindex
  */
  public function doRemoveAdvice($assertionindex) {
    $ret = secureblackbox_samlwriter_do_removeadvice($this->handle, $assertionindex);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes an advice from an assertion.
  *
  * @access   public
  * @param    int    assertionindex
  * @param    int    adviceassertionindex
  */
  public function doRemoveAdviceAssertion($assertionindex, $adviceassertionindex) {
    $ret = secureblackbox_samlwriter_do_removeadviceassertion($this->handle, $assertionindex, $adviceassertionindex);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes all assertions currently configured in the message.
  *
  * @access   public
  */
  public function doRemoveAllAssertions() {
    $ret = secureblackbox_samlwriter_do_removeallassertions($this->handle);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Removes an assertion from the message.
  *
  * @access   public
  * @param    int    assertionindex
  */
  public function doRemoveAssertion($assertionindex) {
    $ret = secureblackbox_samlwriter_do_removeassertion($this->handle, $assertionindex);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the configured message to a string.
  *
  * @access   public
  */
  public function doSave() {
    $ret = secureblackbox_samlwriter_do_save($this->handle);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the configured message to a byte array.
  *
  * @access   public
  */
  public function doSaveBytes() {
    $ret = secureblackbox_samlwriter_do_savebytes($this->handle);
		$err = secureblackbox_samlwriter_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Saves the configured message to a file.
  *
  * @access   public
  * @param    string    filename
  */
  public function doSaveFile($filename) {
    $ret = secureblackbox_samlwriter_do_savefile($this->handle, $filename);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_samlwriter_get($this->handle, 0);
  }
 /**
  * Controls the inclusion of an XML header in the message.
  *
  * @access   public
  */
  public function getAddXMLHeader() {
    return secureblackbox_samlwriter_get($this->handle, 1 );
  }
 /**
  * Controls the inclusion of an XML header in the message.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAddXMLHeader($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 1, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the EndpointIndex entry of the artifact.
  *
  * @access   public
  */
  public function getArtifactEndpointIndex() {
    return secureblackbox_samlwriter_get($this->handle, 2 );
  }
 /**
  * An accessor to the EndpointIndex entry of the artifact.
  *
  * @access   public
  * @param    int   value
  */
  public function setArtifactEndpointIndex($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 2, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the MessageHandle property of the artifact.
  *
  * @access   public
  */
  public function getArtifactMessageHandle() {
    return secureblackbox_samlwriter_get($this->handle, 3 );
  }
 /**
  * An accessor to the MessageHandle property of the artifact.
  *
  * @access   public
  * @param    string   value
  */
  public function setArtifactMessageHandle($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 3, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the contents of the artifact.
  *
  * @access   public
  */
  public function getArtifactRemainingArtifact() {
    return secureblackbox_samlwriter_get($this->handle, 4 );
  }


 /**
  * An accessor to the SourceID property of the artifact.
  *
  * @access   public
  */
  public function getArtifactSourceID() {
    return secureblackbox_samlwriter_get($this->handle, 5 );
  }
 /**
  * An accessor to the SourceID property of the artifact.
  *
  * @access   public
  * @param    string   value
  */
  public function setArtifactSourceID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 5, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The TypeCode property of the artifact.
  *
  * @access   public
  */
  public function getArtifactTypeCode() {
    return secureblackbox_samlwriter_get($this->handle, 6 );
  }
 /**
  * The TypeCode property of the artifact.
  *
  * @access   public
  * @param    int   value
  */
  public function setArtifactTypeCode($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 6, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the URI property of the artifact.
  *
  * @access   public
  */
  public function getArtifactURI() {
    return secureblackbox_samlwriter_get($this->handle, 7 );
  }
 /**
  * An accessor to the URI property of the artifact.
  *
  * @access   public
  * @param    string   value
  */
  public function setArtifactURI($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 7, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the artifact resolve query.
  *
  * @access   public
  */
  public function getArtifactResolveQuery() {
    return secureblackbox_samlwriter_get($this->handle, 8 );
  }
 /**
  * Contains the artifact resolve query.
  *
  * @access   public
  * @param    string   value
  */
  public function setArtifactResolveQuery($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 8, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AssertionAttr arrays.
  *
  * @access   public
  */
  public function getAssertionAttrCount() {
    return secureblackbox_samlwriter_get($this->handle, 9 );
  }
 /**
  * The number of records in the AssertionAttr arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionAttrCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 9, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  */
  public function getAssertionAttrFriendlyName($assertionattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 10 , $assertionattrindex);
  }
 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionAttrFriendlyName($assertionattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 10, $value , $assertionattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  */
  public function getAssertionAttrName($assertionattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 11 , $assertionattrindex);
  }
 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionAttrName($assertionattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 11, $value , $assertionattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  */
  public function getAssertionAttrNameFormat($assertionattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 12 , $assertionattrindex);
  }
 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionAttrNameFormat($assertionattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 12, $value , $assertionattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  */
  public function getAssertionAttrStatementIndex($assertionattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 13 , $assertionattrindex);
  }
 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionAttrStatementIndex($assertionattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 13, $value , $assertionattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains a list of attribute values.
  *
  * @access   public
  */
  public function getAssertionAttrValues($assertionattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 14 , $assertionattrindex);
  }
 /**
  * Contains a list of attribute values.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionAttrValues($assertionattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 14, $value , $assertionattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AssertionCondition arrays.
  *
  * @access   public
  */
  public function getAssertionConditionCount() {
    return secureblackbox_samlwriter_get($this->handle, 15 );
  }
 /**
  * The number of records in the AssertionCondition arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionConditionCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 15, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  */
  public function getAssertionConditionAudienceList($assertionconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 16 , $assertionconditionindex);
  }
 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionConditionAudienceList($assertionconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 16, $value , $assertionconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  */
  public function getAssertionConditionConditionType($assertionconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 17 , $assertionconditionindex);
  }
 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionConditionConditionType($assertionconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 17, $value , $assertionconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  */
  public function getAssertionConditionProxyRestrictionCount($assertionconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 18 , $assertionconditionindex);
  }
 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionConditionProxyRestrictionCount($assertionconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 18, $value , $assertionconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the number of assertions in the message.
  *
  * @access   public
  */
  public function getAssertionCount() {
    return secureblackbox_samlwriter_get($this->handle, 19 );
  }


 /**
  * Contains the References entry of the SAML assertion ID request.
  *
  * @access   public
  */
  public function getAssertionIDRequestReferences() {
    return secureblackbox_samlwriter_get($this->handle, 20 );
  }
 /**
  * Contains the References entry of the SAML assertion ID request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionIDRequestReferences($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 20, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the number of advice assertions.
  *
  * @access   public
  */
  public function getAssertionInfoAdviceAssertionCount() {
    return secureblackbox_samlwriter_get($this->handle, 21 );
  }
 /**
  * Contains the number of advice assertions.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionInfoAdviceAssertionCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 21, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the type of the assertion.
  *
  * @access   public
  */
  public function getAssertionInfoAssertionType() {
    return secureblackbox_samlwriter_get($this->handle, 22 );
  }
 /**
  * Specifies the type of the assertion.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionInfoAssertionType($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 22, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getAssertionInfoChainValidationDetails() {
    return secureblackbox_samlwriter_get($this->handle, 23 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getAssertionInfoChainValidationResult() {
    return secureblackbox_samlwriter_get($this->handle, 24 );
  }


 /**
  * Represents the Conditions.
  *
  * @access   public
  */
  public function getAssertionInfoConditionsNotBefore() {
    return secureblackbox_samlwriter_get($this->handle, 25 );
  }
 /**
  * Represents the Conditions.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoConditionsNotBefore($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 25, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the Conditions.
  *
  * @access   public
  */
  public function getAssertionInfoConditionsNotOnOrAfter() {
    return secureblackbox_samlwriter_get($this->handle, 26 );
  }
 /**
  * Represents the Conditions.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoConditionsNotOnOrAfter($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 26, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the encrypted assertion content.
  *
  * @access   public
  */
  public function getAssertionInfoEncryptedContent() {
    return secureblackbox_samlwriter_get($this->handle, 27 );
  }
 /**
  * Represents the encrypted assertion content.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoEncryptedContent($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 27, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents the ID of the assertion.
  *
  * @access   public
  */
  public function getAssertionInfoID() {
    return secureblackbox_samlwriter_get($this->handle, 28 );
  }
 /**
  * Represents the ID of the assertion.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 28, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents an ID reference value.
  *
  * @access   public
  */
  public function getAssertionInfoIDRef() {
    return secureblackbox_samlwriter_get($this->handle, 29 );
  }
 /**
  * Represents an ID reference value.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoIDRef($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 29, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the assertion issuance time stamp.
  *
  * @access   public
  */
  public function getAssertionInfoIssueInstant() {
    return secureblackbox_samlwriter_get($this->handle, 30 );
  }
 /**
  * Contains the assertion issuance time stamp.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoIssueInstant($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 30, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The outcome of the cryptographic signature validation.
  *
  * @access   public
  */
  public function getAssertionInfoSignatureValidationResult() {
    return secureblackbox_samlwriter_get($this->handle, 31 );
  }


 /**
  * Specifies whether the assertion is signed.
  *
  * @access   public
  */
  public function getAssertionInfoSigned() {
    return secureblackbox_samlwriter_get($this->handle, 32 );
  }
 /**
  * Specifies whether the assertion is signed.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAssertionInfoSigned($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 32, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Represents an URI reference value.
  *
  * @access   public
  */
  public function getAssertionInfoURIRef() {
    return secureblackbox_samlwriter_get($this->handle, 33 );
  }
 /**
  * Represents an URI reference value.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoURIRef($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 33, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the signing certificate's chain validation log.
  *
  * @access   public
  */
  public function getAssertionInfoValidationLog() {
    return secureblackbox_samlwriter_get($this->handle, 34 );
  }


 /**
  * Specifies the SAML protocol version used.
  *
  * @access   public
  */
  public function getAssertionInfoVersion() {
    return secureblackbox_samlwriter_get($this->handle, 35 );
  }
 /**
  * Specifies the SAML protocol version used.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionInfoVersion($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 35, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the assertion issuer.
  *
  * @access   public
  */
  public function getAssertionIssuer() {
    return secureblackbox_samlwriter_get($this->handle, 36 );
  }
 /**
  * Specifies the assertion issuer.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionIssuer($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 36, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AssertionStatement arrays.
  *
  * @access   public
  */
  public function getAssertionStatementCount() {
    return secureblackbox_samlwriter_get($this->handle, 37 );
  }
 /**
  * The number of records in the AssertionStatement arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionStatementCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 37, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains a list of statement attribute names.
  *
  * @access   public
  */
  public function getAssertionStatementAttributes($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 38 , $assertionstatementindex);
  }
 /**
  * Contains a list of statement attribute names.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAttributes($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 38, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the list of authenticating authorities.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnContextAuthenticatingAuthorities($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 39 , $assertionstatementindex);
  }
 /**
  * Contains the list of authenticating authorities.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnContextAuthenticatingAuthorities($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 39, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication context choice variant.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnContextChoice($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 40 , $assertionstatementindex);
  }
 /**
  * Specifies the authentication context choice variant.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnContextChoice($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 40, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the authentication contexts class reference.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnContextClassRef($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 41 , $assertionstatementindex);
  }
 /**
  * Indicates the authentication contexts class reference.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnContextClassRef($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 41, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication contexts declaration.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnContextDecl($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 42 , $assertionstatementindex);
  }
 /**
  * Specifies the authentication contexts declaration.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnContextDecl($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 42, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication contexts declaration reference.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnContextDeclRef($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 43 , $assertionstatementindex);
  }
 /**
  * Specifies the authentication contexts declaration reference.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnContextDeclRef($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 43, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication event timestamp.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnInstant($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 44 , $assertionstatementindex);
  }
 /**
  * Specifies the authentication event timestamp.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnInstant($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 44, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the authentication session index.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnSessionIndex($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 45 , $assertionstatementindex);
  }
 /**
  * Contains the authentication session index.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnSessionIndex($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 45, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Maps to the SessionNotOnOrAfter parameter of the authentication statement.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnSessionNotOnOrAfter($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 46 , $assertionstatementindex);
  }
 /**
  * Maps to the SessionNotOnOrAfter parameter of the authentication statement.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnSessionNotOnOrAfter($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 46, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication subjects address.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnSubjectLocalityAddress($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 47 , $assertionstatementindex);
  }
 /**
  * Specifies the authentication subjects address.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnSubjectLocalityAddress($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 47, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Maps to the authentication subjects DNS name parameter.
  *
  * @access   public
  */
  public function getAssertionStatementAuthnSubjectLocalityDNSName($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 48 , $assertionstatementindex);
  }
 /**
  * Maps to the authentication subjects DNS name parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthnSubjectLocalityDNSName($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 48, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the list of actions of the authorization statement.
  *
  * @access   public
  */
  public function getAssertionStatementAuthzActions($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 49 , $assertionstatementindex);
  }
 /**
  * Provides access to the list of actions of the authorization statement.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthzActions($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 49, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authorization decision.
  *
  * @access   public
  */
  public function getAssertionStatementAuthzDecision($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 50 , $assertionstatementindex);
  }
 /**
  * Specifies the authorization decision.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionStatementAuthzDecision($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 50, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Manages the authorization decision statement evidence parameter.
  *
  * @access   public
  */
  public function getAssertionStatementAuthzDecisionEvidence($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 51 , $assertionstatementindex);
  }
 /**
  * Manages the authorization decision statement evidence parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthzDecisionEvidence($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 51, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authorization decision statement resource parameter.
  *
  * @access   public
  */
  public function getAssertionStatementAuthzDecisionResource($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 52 , $assertionstatementindex);
  }
 /**
  * Specifies the authorization decision statement resource parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionStatementAuthzDecisionResource($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 52, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the assertion statement type.
  *
  * @access   public
  */
  public function getAssertionStatementStatementType($assertionstatementindex) {
    return secureblackbox_samlwriter_get($this->handle, 53 , $assertionstatementindex);
  }
 /**
  * Specifies the assertion statement type.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionStatementStatementType($assertionstatementindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 53, $value , $assertionstatementindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AssertionSubjectConfirmation arrays.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationCount() {
    return secureblackbox_samlwriter_get($this->handle, 54 );
  }
 /**
  * The number of records in the AssertionSubjectConfirmation arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAssertionSubjectConfirmationCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 54, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataAddress($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 55 , $assertionsubjectconfirmationindex);
  }
 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataAddress($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 55, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataInResponseTo($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 56 , $assertionsubjectconfirmationindex);
  }
 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataInResponseTo($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 56, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataNotBefore($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 57 , $assertionsubjectconfirmationindex);
  }
 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataNotBefore($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 57, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataNotOnOrAfter($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 58 , $assertionsubjectconfirmationindex);
  }
 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataNotOnOrAfter($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 58, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataRecipient($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 59 , $assertionsubjectconfirmationindex);
  }
 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataRecipient($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 59, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationDataType($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 60 , $assertionsubjectconfirmationindex);
  }
 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationDataType($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 60, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationID($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 61 , $assertionsubjectconfirmationindex);
  }
 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationID($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 61, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  */
  public function getAssertionSubjectConfirmationMethod($assertionsubjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 62 , $assertionsubjectconfirmationindex);
  }
 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectConfirmationMethod($assertionsubjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 62, $value , $assertionsubjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the assertion subject ID.
  *
  * @access   public
  */
  public function getAssertionSubjectID() {
    return secureblackbox_samlwriter_get($this->handle, 63 );
  }
 /**
  * Specifies the assertion subject ID.
  *
  * @access   public
  * @param    string   value
  */
  public function setAssertionSubjectID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 63, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AttrQueryAttr arrays.
  *
  * @access   public
  */
  public function getAttrQueryAttrCount() {
    return secureblackbox_samlwriter_get($this->handle, 64 );
  }
 /**
  * The number of records in the AttrQueryAttr arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAttrQueryAttrCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 64, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  */
  public function getAttrQueryAttrFriendlyName($attrqueryattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 65 , $attrqueryattrindex);
  }
 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  * @param    string   value
  */
  public function setAttrQueryAttrFriendlyName($attrqueryattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 65, $value , $attrqueryattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  */
  public function getAttrQueryAttrName($attrqueryattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 66 , $attrqueryattrindex);
  }
 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  * @param    string   value
  */
  public function setAttrQueryAttrName($attrqueryattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 66, $value , $attrqueryattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  */
  public function getAttrQueryAttrNameFormat($attrqueryattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 67 , $attrqueryattrindex);
  }
 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  * @param    string   value
  */
  public function setAttrQueryAttrNameFormat($attrqueryattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 67, $value , $attrqueryattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  */
  public function getAttrQueryAttrStatementIndex($attrqueryattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 68 , $attrqueryattrindex);
  }
 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  * @param    int   value
  */
  public function setAttrQueryAttrStatementIndex($attrqueryattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 68, $value , $attrqueryattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains a list of attribute values.
  *
  * @access   public
  */
  public function getAttrQueryAttrValues($attrqueryattrindex) {
    return secureblackbox_samlwriter_get($this->handle, 69 , $attrqueryattrindex);
  }
 /**
  * Contains a list of attribute values.
  *
  * @access   public
  * @param    string   value
  */
  public function setAttrQueryAttrValues($attrqueryattrindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 69, $value , $attrqueryattrindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the authentication context comparison method.
  *
  * @access   public
  */
  public function getAuthnQueryComparison() {
    return secureblackbox_samlwriter_get($this->handle, 70 );
  }
 /**
  * Specifies the authentication context comparison method.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnQueryComparison($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 70, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the context class reference.
  *
  * @access   public
  */
  public function getAuthnQueryContextClassRefs() {
    return secureblackbox_samlwriter_get($this->handle, 71 );
  }
 /**
  * Specifies the context class reference.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnQueryContextClassRefs($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the context reference type.
  *
  * @access   public
  */
  public function getAuthnQueryRefType() {
    return secureblackbox_samlwriter_get($this->handle, 72 );
  }
 /**
  * Specifies the context reference type.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnQueryRefType($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 72, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the index of the session to the authentication entity.
  *
  * @access   public
  */
  public function getAuthnQuerySessionIndex() {
    return secureblackbox_samlwriter_get($this->handle, 73 );
  }
 /**
  * Specifies the index of the session to the authentication entity.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnQuerySessionIndex($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 73, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the assertion consumer service index.
  *
  * @access   public
  */
  public function getAuthnRequestAssertionConsumerServiceIndex() {
    return secureblackbox_samlwriter_get($this->handle, 74 );
  }
 /**
  * Specifies the assertion consumer service index.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestAssertionConsumerServiceIndex($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the assertion consumer service URL.
  *
  * @access   public
  */
  public function getAuthnRequestAssertionConsumerServiceURL() {
    return secureblackbox_samlwriter_get($this->handle, 75 );
  }
 /**
  * Specifies the assertion consumer service URL.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestAssertionConsumerServiceURL($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 75, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the attribute consuming service index.
  *
  * @access   public
  */
  public function getAuthnRequestAttributeConsumingServiceIndex() {
    return secureblackbox_samlwriter_get($this->handle, 76 );
  }
 /**
  * Specifies the attribute consuming service index.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestAttributeConsumingServiceIndex($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 76, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the NotBefore condition of the request.
  *
  * @access   public
  */
  public function getAuthnRequestConditionsNotBefore() {
    return secureblackbox_samlwriter_get($this->handle, 77 );
  }
 /**
  * Specifies the NotBefore condition of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestConditionsNotBefore($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 77, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the NotOnOrAfter condition of the request.
  *
  * @access   public
  */
  public function getAuthnRequestConditionsNotOnOrAfter() {
    return secureblackbox_samlwriter_get($this->handle, 78 );
  }
 /**
  * Provides access to the NotOnOrAfter condition of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestConditionsNotOnOrAfter($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 78, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Provides access to the authentication context class references.
  *
  * @access   public
  */
  public function getAuthnRequestContextClassRefs() {
    return secureblackbox_samlwriter_get($this->handle, 79 );
  }
 /**
  * Provides access to the authentication context class references.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestContextClassRefs($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 79, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the AuthnContext comparison method.
  *
  * @access   public
  */
  public function getAuthnRequestContextComparison() {
    return secureblackbox_samlwriter_get($this->handle, 80 );
  }
 /**
  * Specifies the AuthnContext comparison method.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestContextComparison($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 80, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the context reference type.
  *
  * @access   public
  */
  public function getAuthnRequestContextRefType() {
    return secureblackbox_samlwriter_get($this->handle, 81 );
  }
 /**
  * Specifies the context reference type.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestContextRefType($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 81, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Corresponds to the ForceAuthn parameter of the request.
  *
  * @access   public
  */
  public function getAuthnRequestForceAuthn() {
    return secureblackbox_samlwriter_get($this->handle, 82 );
  }
 /**
  * Corresponds to the ForceAuthn parameter of the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestForceAuthn($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 82, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Maps to the IsPassive parameter of the request.
  *
  * @access   public
  */
  public function getAuthnRequestIsPassive() {
    return secureblackbox_samlwriter_get($this->handle, 83 );
  }
 /**
  * Maps to the IsPassive parameter of the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestIsPassive($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 83, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Matches the AllowCreate attribute of NameIDPolicy element of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyAllowCreate() {
    return secureblackbox_samlwriter_get($this->handle, 84 );
  }
 /**
  * Matches the AllowCreate attribute of NameIDPolicy element of the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestNameIDPolicyAllowCreate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 84, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Matches to the Format attribute of the NameIDPolicy element of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyFormat() {
    return secureblackbox_samlwriter_get($this->handle, 85 );
  }
 /**
  * Matches to the Format attribute of the NameIDPolicy element of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestNameIDPolicyFormat($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 85, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Matches to the SP name qualifier attribute of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicySPNameQualifier() {
    return secureblackbox_samlwriter_get($this->handle, 86 );
  }
 /**
  * Matches to the SP name qualifier attribute of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestNameIDPolicySPNameQualifier($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 86, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Controls inclusion of AllowCreate attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyUseAllowCreate() {
    return secureblackbox_samlwriter_get($this->handle, 87 );
  }
 /**
  * Controls inclusion of AllowCreate attribute in the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestNameIDPolicyUseAllowCreate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 87, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the protocol binding to be requested in the authentication request.
  *
  * @access   public
  */
  public function getAuthnRequestProtocolBinding() {
    return secureblackbox_samlwriter_get($this->handle, 88 );
  }
 /**
  * Specifies the protocol binding to be requested in the authentication request.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestProtocolBinding($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 88, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the name of the requestor.
  *
  * @access   public
  */
  public function getAuthnRequestProviderName() {
    return secureblackbox_samlwriter_get($this->handle, 89 );
  }
 /**
  * Specifies the name of the requestor.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestProviderName($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 89, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Matches the GetComplete element of the IDPList entry of the Scoping object.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPListGetComplete() {
    return secureblackbox_samlwriter_get($this->handle, 90 );
  }
 /**
  * Matches the GetComplete element of the IDPList entry of the Scoping object.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestScopingIDPListGetComplete($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of proxies on the way between the requestor and the provider.
  *
  * @access   public
  */
  public function getAuthnRequestScopingProxyCount() {
    return secureblackbox_samlwriter_get($this->handle, 91 );
  }
 /**
  * The maximum number of proxies on the way between the requestor and the provider.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestScopingProxyCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 91, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A collection of requestor IDs on whose behalf the request is being sent.
  *
  * @access   public
  */
  public function getAuthnRequestScopingRequesterIDs() {
    return secureblackbox_samlwriter_get($this->handle, 92 );
  }
 /**
  * A collection of requestor IDs on whose behalf the request is being sent.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestScopingRequesterIDs($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 92, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Controls inclusion of ForceAuthn attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestUseForceAuthn() {
    return secureblackbox_samlwriter_get($this->handle, 93 );
  }
 /**
  * Controls inclusion of ForceAuthn attribute in the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestUseForceAuthn($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 93, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Controls inclusion of IsPassive attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestUseIsPassive() {
    return secureblackbox_samlwriter_get($this->handle, 94 );
  }
 /**
  * Controls inclusion of IsPassive attribute in the request.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setAuthnRequestUseIsPassive($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 94, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AuthnRequestCondition arrays.
  *
  * @access   public
  */
  public function getAuthnRequestConditionCount() {
    return secureblackbox_samlwriter_get($this->handle, 95 );
  }
 /**
  * The number of records in the AuthnRequestCondition arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestConditionCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 95, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  */
  public function getAuthnRequestConditionAudienceList($authnrequestconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 96 , $authnrequestconditionindex);
  }
 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestConditionAudienceList($authnrequestconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 96, $value , $authnrequestconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  */
  public function getAuthnRequestConditionConditionType($authnrequestconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 97 , $authnrequestconditionindex);
  }
 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestConditionConditionType($authnrequestconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 97, $value , $authnrequestconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  */
  public function getAuthnRequestConditionProxyRestrictionCount($authnrequestconditionindex) {
    return secureblackbox_samlwriter_get($this->handle, 98 , $authnrequestconditionindex);
  }
 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestConditionProxyRestrictionCount($authnrequestconditionindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 98, $value , $authnrequestconditionindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the AuthnRequestScopingIDP arrays.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPCount() {
    return secureblackbox_samlwriter_get($this->handle, 99 );
  }
 /**
  * The number of records in the AuthnRequestScopingIDP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setAuthnRequestScopingIDPCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 99, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the Loc attribute.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPLoc($authnrequestscopingidpindex) {
    return secureblackbox_samlwriter_get($this->handle, 100 , $authnrequestscopingidpindex);
  }
 /**
  * Contains the value of the Loc attribute.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestScopingIDPLoc($authnrequestscopingidpindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 100, $value , $authnrequestscopingidpindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the name of the IdP provider.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPName($authnrequestscopingidpindex) {
    return secureblackbox_samlwriter_get($this->handle, 101 , $authnrequestscopingidpindex);
  }
 /**
  * Contains the name of the IdP provider.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestScopingIDPName($authnrequestscopingidpindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 101, $value , $authnrequestscopingidpindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the provider ID.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPProviderID($authnrequestscopingidpindex) {
    return secureblackbox_samlwriter_get($this->handle, 102 , $authnrequestscopingidpindex);
  }
 /**
  * Contains the provider ID.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthnRequestScopingIDPProviderID($authnrequestscopingidpindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 102, $value , $authnrequestscopingidpindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the list of actions included in the query.
  *
  * @access   public
  */
  public function getAuthzDecisionQueryActions() {
    return secureblackbox_samlwriter_get($this->handle, 103 );
  }
 /**
  * Specifies the list of actions included in the query.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthzDecisionQueryActions($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 103, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Matches the Resource element of the query.
  *
  * @access   public
  */
  public function getAuthzDecisionQueryResource() {
    return secureblackbox_samlwriter_get($this->handle, 104 );
  }
 /**
  * Matches the Resource element of the query.
  *
  * @access   public
  * @param    string   value
  */
  public function setAuthzDecisionQueryResource($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 104, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the type of the binding to use.
  *
  * @access   public
  */
  public function getBinding() {
    return secureblackbox_samlwriter_get($this->handle, 105 );
  }
 /**
  * Specifies the type of the binding to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setBinding($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 105, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the Consent parameter of the request.
  *
  * @access   public
  */
  public function getConsent() {
    return secureblackbox_samlwriter_get($this->handle, 106 );
  }
 /**
  * Contains the Consent parameter of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setConsent($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 106, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the Destination parameter of the SAML object.
  *
  * @access   public
  */
  public function getDestination() {
    return secureblackbox_samlwriter_get($this->handle, 107 );
  }
 /**
  * Contains the Destination parameter of the SAML object.
  *
  * @access   public
  * @param    string   value
  */
  public function setDestination($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 107, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getEncryptionCertBytes() {
    return secureblackbox_samlwriter_get($this->handle, 108 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getEncryptionCertHandle() {
    return secureblackbox_samlwriter_get($this->handle, 109 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setEncryptionCertHandle($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 109, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the request.
  *
  * @access   public
  */
  public function getID() {
    return secureblackbox_samlwriter_get($this->handle, 110 );
  }
 /**
  * The ID of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 110, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the InResponseTo property of the SAML request.
  *
  * @access   public
  */
  public function getInResponseTo() {
    return secureblackbox_samlwriter_get($this->handle, 111 );
  }
 /**
  * Contains the InResponseTo property of the SAML request.
  *
  * @access   public
  * @param    string   value
  */
  public function setInResponseTo($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 111, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains request issuance timestamp.
  *
  * @access   public
  */
  public function getIssueInstant() {
    return secureblackbox_samlwriter_get($this->handle, 112 );
  }
 /**
  * Contains request issuance timestamp.
  *
  * @access   public
  * @param    string   value
  */
  public function setIssueInstant($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 112, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets the issuer of the message.
  *
  * @access   public
  */
  public function getIssuer() {
    return secureblackbox_samlwriter_get($this->handle, 113 );
  }
 /**
  * Sets the issuer of the message.
  *
  * @access   public
  * @param    string   value
  */
  public function setIssuer($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 113, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NameID parameter.
  *
  * @access   public
  */
  public function getLogoutRequestNameID() {
    return secureblackbox_samlwriter_get($this->handle, 114 );
  }
 /**
  * Contains the value of the NameID parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setLogoutRequestNameID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 114, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NotOnOrAfter parameter.
  *
  * @access   public
  */
  public function getLogoutRequestNotOnOrAfter() {
    return secureblackbox_samlwriter_get($this->handle, 115 );
  }
 /**
  * Contains the value of the NotOnOrAfter parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setLogoutRequestNotOnOrAfter($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 115, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the Reason parameter.
  *
  * @access   public
  */
  public function getLogoutRequestReason() {
    return secureblackbox_samlwriter_get($this->handle, 116 );
  }
 /**
  * Contains the value of the Reason parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setLogoutRequestReason($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 116, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the list of session indices.
  *
  * @access   public
  */
  public function getLogoutRequestSessionIndexes() {
    return secureblackbox_samlwriter_get($this->handle, 117 );
  }
 /**
  * Contains the list of session indices.
  *
  * @access   public
  * @param    string   value
  */
  public function setLogoutRequestSessionIndexes($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 117, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NameID parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestNameID() {
    return secureblackbox_samlwriter_get($this->handle, 118 );
  }
 /**
  * Contains the value of the NameID parameter of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setManageNameIDRequestNameID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 118, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NewEncryptedID parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestNewEncryptedID() {
    return secureblackbox_samlwriter_get($this->handle, 119 );
  }
 /**
  * Contains the value of the NewEncryptedID parameter of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setManageNameIDRequestNewEncryptedID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 119, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NewID parameter.
  *
  * @access   public
  */
  public function getManageNameIDRequestNewID() {
    return secureblackbox_samlwriter_get($this->handle, 120 );
  }
 /**
  * Contains the value of the NewID parameter.
  *
  * @access   public
  * @param    string   value
  */
  public function setManageNameIDRequestNewID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 120, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the Terminate parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestTerminate() {
    return secureblackbox_samlwriter_get($this->handle, 121 );
  }
 /**
  * Contains the value of the Terminate parameter of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setManageNameIDRequestTerminate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 121, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An accessor to the NameID parameter of the request.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameID() {
    return secureblackbox_samlwriter_get($this->handle, 122 );
  }
 /**
  * An accessor to the NameID parameter of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setNameIDMappingRequestNameID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 122, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of AllowCreate parameter of the NameIDPolicy object.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyAllowCreate() {
    return secureblackbox_samlwriter_get($this->handle, 123 );
  }
 /**
  * Contains the value of AllowCreate parameter of the NameIDPolicy object.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setNameIDMappingRequestNameIDPolicyAllowCreate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 123, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the format of the NameIDPolicy element.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyFormat() {
    return secureblackbox_samlwriter_get($this->handle, 124 );
  }
 /**
  * Specifies the format of the NameIDPolicy element.
  *
  * @access   public
  * @param    string   value
  */
  public function setNameIDMappingRequestNameIDPolicyFormat($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 124, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the SPNameQualifier parameter of the NameIDPolicy element.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicySPNameQualifier() {
    return secureblackbox_samlwriter_get($this->handle, 125 );
  }
 /**
  * Contains the SPNameQualifier parameter of the NameIDPolicy element.
  *
  * @access   public
  * @param    string   value
  */
  public function setNameIDMappingRequestNameIDPolicySPNameQualifier($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 125, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Controls inclusion of UseAllow modifier in the NameIDPolicy object.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyUseAllowCreate() {
    return secureblackbox_samlwriter_get($this->handle, 126 );
  }
 /**
  * Controls inclusion of UseAllow modifier in the NameIDPolicy object.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setNameIDMappingRequestNameIDPolicyUseAllowCreate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 126, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the SAML type of message being created.
  *
  * @access   public
  */
  public function getOutputType() {
    return secureblackbox_samlwriter_get($this->handle, 127 );
  }


 /**
  * Contains the form body.
  *
  * @access   public
  */
  public function getPOSTBindingBody() {
    return secureblackbox_samlwriter_get($this->handle, 128 );
  }
 /**
  * Contains the form body.
  *
  * @access   public
  * @param    string   value
  */
  public function setPOSTBindingBody($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 128, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the XHTML form template returned by the service provider.
  *
  * @access   public
  */
  public function getPOSTBindingFormTemplate() {
    return secureblackbox_samlwriter_get($this->handle, 129 );
  }
 /**
  * Contains the XHTML form template returned by the service provider.
  *
  * @access   public
  * @param    string   value
  */
  public function setPOSTBindingFormTemplate($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 129, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether binding is applied on a server, or on a client side.
  *
  * @access   public
  */
  public function getPOSTBindingMode() {
    return secureblackbox_samlwriter_get($this->handle, 130 );
  }
 /**
  * Specifies whether binding is applied on a server, or on a client side.
  *
  * @access   public
  * @param    int   value
  */
  public function setPOSTBindingMode($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 130, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the RelayState parameter of POST binding mechanism.
  *
  * @access   public
  */
  public function getPOSTBindingRelayState() {
    return secureblackbox_samlwriter_get($this->handle, 131 );
  }
 /**
  * Contains the value of the RelayState parameter of POST binding mechanism.
  *
  * @access   public
  * @param    string   value
  */
  public function setPOSTBindingRelayState($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 131, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the URL of POST binding mechanism.
  *
  * @access   public
  */
  public function getPOSTBindingURL() {
    return secureblackbox_samlwriter_get($this->handle, 132 );
  }
 /**
  * Contains the URL of POST binding mechanism.
  *
  * @access   public
  * @param    string   value
  */
  public function setPOSTBindingURL($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 132, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  */
  public function getProfile() {
    return secureblackbox_samlwriter_get($this->handle, 133 );
  }
 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setProfile($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 133, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the message encoding.
  *
  * @access   public
  */
  public function getRedirectBindingEncoding() {
    return secureblackbox_samlwriter_get($this->handle, 134 );
  }
 /**
  * Specifies the message encoding.
  *
  * @access   public
  * @param    string   value
  */
  public function setRedirectBindingEncoding($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 134, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enforces a signature over all outgoing messages.
  *
  * @access   public
  */
  public function getRedirectBindingForceSign() {
    return secureblackbox_samlwriter_get($this->handle, 135 );
  }
 /**
  * Enforces a signature over all outgoing messages.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setRedirectBindingForceSign($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 135, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the RelayState parameter of the binding.
  *
  * @access   public
  */
  public function getRedirectBindingRelayState() {
    return secureblackbox_samlwriter_get($this->handle, 136 );
  }
 /**
  * Contains the RelayState parameter of the binding.
  *
  * @access   public
  * @param    string   value
  */
  public function setRedirectBindingRelayState($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 136, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether to sign generated messages.
  *
  * @access   public
  */
  public function getRedirectBindingSign() {
    return secureblackbox_samlwriter_get($this->handle, 137 );
  }
 /**
  * Specifies whether to sign generated messages.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setRedirectBindingSign($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 137, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the signature algorithm.
  *
  * @access   public
  */
  public function getRedirectBindingSignatureAlgorithm() {
    return secureblackbox_samlwriter_get($this->handle, 138 );
  }
 /**
  * Contains the signature algorithm.
  *
  * @access   public
  * @param    string   value
  */
  public function setRedirectBindingSignatureAlgorithm($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 138, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the URL of the request query.
  *
  * @access   public
  */
  public function getRedirectBindingURL() {
    return secureblackbox_samlwriter_get($this->handle, 139 );
  }
 /**
  * Contains the URL of the request query.
  *
  * @access   public
  * @param    string   value
  */
  public function setRedirectBindingURL($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 139, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Instructs the class whether to verify incoming signatures.
  *
  * @access   public
  */
  public function getRedirectBindingVerifySignatures() {
    return secureblackbox_samlwriter_get($this->handle, 140 );
  }
 /**
  * Instructs the class whether to verify incoming signatures.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setRedirectBindingVerifySignatures($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 140, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getRedirectBindingCertBytes() {
    return secureblackbox_samlwriter_get($this->handle, 141 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getRedirectBindingCertHandle() {
    return secureblackbox_samlwriter_get($this->handle, 142 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setRedirectBindingCertHandle($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 142, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the NameID parameter of a NameIDMapping response.
  *
  * @access   public
  */
  public function getResponseNameID() {
    return secureblackbox_samlwriter_get($this->handle, 143 );
  }
 /**
  * Contains the NameID parameter of a NameIDMapping response.
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseNameID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 143, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * An optional message element to be returned with the response.
  *
  * @access   public
  */
  public function getResponseOptionalElement() {
    return secureblackbox_samlwriter_get($this->handle, 144 );
  }
 /**
  * An optional message element to be returned with the response.
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseOptionalElement($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 144, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the type of the response.
  *
  * @access   public
  */
  public function getResponseResponseType() {
    return secureblackbox_samlwriter_get($this->handle, 145 );
  }
 /**
  * Contains the type of the response.
  *
  * @access   public
  * @param    int   value
  */
  public function setResponseResponseType($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 145, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The value of the nested StatusCode.
  *
  * @access   public
  */
  public function getResponseStatusCodeSubValue() {
    return secureblackbox_samlwriter_get($this->handle, 146 );
  }
 /**
  * The value of the nested StatusCode.
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseStatusCodeSubValue($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 146, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the status code value.
  *
  * @access   public
  */
  public function getResponseStatusCodeValue() {
    return secureblackbox_samlwriter_get($this->handle, 147 );
  }
 /**
  * Contains the status code value.
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseStatusCodeValue($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 147, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains additional information on the status of the request.
  *
  * @access   public
  */
  public function getResponseStatusDetail() {
    return secureblackbox_samlwriter_get($this->handle, 148 );
  }
 /**
  * Contains additional information on the status of the request.
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseStatusDetail($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 148, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains a status message (optional).
  *
  * @access   public
  */
  public function getResponseStatusMessage() {
    return secureblackbox_samlwriter_get($this->handle, 149 );
  }
 /**
  * Contains a status message (optional).
  *
  * @access   public
  * @param    string   value
  */
  public function setResponseStatusMessage($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 149, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether the created SAML message should be signed.
  *
  * @access   public
  */
  public function getSign() {
    return secureblackbox_samlwriter_get($this->handle, 150 );
  }
 /**
  * Specifies whether the created SAML message should be signed.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSign($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 150, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_samlwriter_get($this->handle, 151 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_samlwriter_get($this->handle, 152 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningCertHandle($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 152, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  */
  public function getSigningChainCount() {
    return secureblackbox_samlwriter_get($this->handle, 153 );
  }
 /**
  * The number of records in the SigningChain arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setSigningChainCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 153, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningChainBytes($signingchainindex) {
    return secureblackbox_samlwriter_get($this->handle, 154 , $signingchainindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningChainHandle($signingchainindex) {
    return secureblackbox_samlwriter_get($this->handle, 155 , $signingchainindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setSigningChainHandle($signingchainindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 155, $value , $signingchainindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SubjectConfirmation arrays.
  *
  * @access   public
  */
  public function getSubjectConfirmationCount() {
    return secureblackbox_samlwriter_get($this->handle, 156 );
  }
 /**
  * The number of records in the SubjectConfirmation arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setSubjectConfirmationCount($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 156, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataAddress($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 157 , $subjectconfirmationindex);
  }
 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataAddress($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 157, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataInResponseTo($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 158 , $subjectconfirmationindex);
  }
 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataInResponseTo($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 158, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataNotBefore($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 159 , $subjectconfirmationindex);
  }
 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataNotBefore($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 159, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataNotOnOrAfter($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 160 , $subjectconfirmationindex);
  }
 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataNotOnOrAfter($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 160, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataRecipient($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 161 , $subjectconfirmationindex);
  }
 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataRecipient($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 161, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataType($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 162 , $subjectconfirmationindex);
  }
 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationDataType($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 162, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  */
  public function getSubjectConfirmationID($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 163 , $subjectconfirmationindex);
  }
 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationID($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 163, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  */
  public function getSubjectConfirmationMethod($subjectconfirmationindex) {
    return secureblackbox_samlwriter_get($this->handle, 164 , $subjectconfirmationindex);
  }
 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectConfirmationMethod($subjectconfirmationindex, $value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 164, $value , $subjectconfirmationindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Sets the subject of the message.
  *
  * @access   public
  */
  public function getSubjectID() {
    return secureblackbox_samlwriter_get($this->handle, 165 );
  }
 /**
  * Sets the subject of the message.
  *
  * @access   public
  * @param    string   value
  */
  public function setSubjectID($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 165, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the protocol version of the SAML message.
  *
  * @access   public
  */
  public function getVersion() {
    return secureblackbox_samlwriter_get($this->handle, 166 );
  }
 /**
  * Specifies the protocol version of the SAML message.
  *
  * @access   public
  * @param    string   value
  */
  public function setVersion($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 166, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }



  public function getRuntimeLicense() {
    return secureblackbox_samlwriter_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_samlwriter_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlwriter_get_last_error($this->handle));
    }
    return $ret;
  }
  
 /**
  * Fires to report an error condition.
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
