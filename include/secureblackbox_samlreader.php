<?php

require_once('secureblackbox_keys.php');

/**
 * SecureBlackbox 2020 PHP Edition - SAMLReader Component
 *
 * Copyright (c) 2020 /n software inc. - All rights reserved.
 *
 * For more information, please visit http://www.nsoftware.com/.
 *
 */

class SecureBlackbox_SAMLReader {
  
  var $handle;

  public function __construct() {
    $this->handle = secureblackbox_samlreader_open(SECUREBLACKBOX_OEMKEY_787);
    secureblackbox_samlreader_register_callback($this->handle, 1, array($this, 'fireError'));
    secureblackbox_samlreader_register_callback($this->handle, 2, array($this, 'fireNotification'));
    secureblackbox_samlreader_register_callback($this->handle, 3, array($this, 'fireSignatureFound'));
    secureblackbox_samlreader_register_callback($this->handle, 4, array($this, 'fireSignatureValidated'));
  }
  
  public function __destruct() {
    secureblackbox_samlreader_close($this->handle);
  }

 /**
  * Returns the last error code.
  *
  * @access   public
  */
  public function lastError() {
    return secureblackbox_samlreader_get_last_error($this->handle);
  }
  
 /**
  * Returns the last error message.
  *
  * @access   public
  */
  public function lastErrorCode() {
    return secureblackbox_samlreader_get_last_error_code($this->handle);
  }

 /**
  * Compares two SAML IDs.
  *
  * @access   public
  * @param    string    id1
  * @param    string    id2
  */
  public function doCompareIDs($id1, $id2) {
    $ret = secureblackbox_samlreader_do_compareids($this->handle, $id1, $id2);
		$err = 0;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
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
    $ret = secureblackbox_samlreader_do_config($this->handle, $configurationstring);
		$err = secureblackbox_samlreader_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Extracts a specific property from a SAML ID.
  *
  * @access   public
  * @param    string    id
  * @param    string    propname
  */
  public function doGetIDProp($id, $propname) {
    $ret = secureblackbox_samlreader_do_getidprop($this->handle, $id, $propname);
		$err = secureblackbox_samlreader_get_last_error_code($this->handle);
    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens a SAML entity.
  *
  * @access   public
  * @param    string    input
  */
  public function doOpen($input) {
    $ret = secureblackbox_samlreader_do_open($this->handle, $input);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens a SAML entity.
  *
  * @access   public
  * @param    string    inputbytes
  */
  public function doOpenBytes($inputbytes) {
    $ret = secureblackbox_samlreader_do_openbytes($this->handle, $inputbytes);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Opens a SAML entity.
  *
  * @access   public
  * @param    string    inputfile
  */
  public function doOpenFile($inputfile) {
    $ret = secureblackbox_samlreader_do_openfile($this->handle, $inputfile);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Pins advice assertion by propagating it in PinnedAssertionXXX properties.
  *
  * @access   public
  * @param    int    assertionindex
  * @param    int    adviceassertionindex
  */
  public function doPinAdviceAssertion($assertionindex, $adviceassertionindex) {
    $ret = secureblackbox_samlreader_do_pinadviceassertion($this->handle, $assertionindex, $adviceassertionindex);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Pins assertion by propagating it in PinnedAssertionXXX properties.
  *
  * @access   public
  * @param    int    assertionindex
  */
  public function doPinAssertion($assertionindex) {
    $ret = secureblackbox_samlreader_do_pinassertion($this->handle, $assertionindex);
		$err = $ret;

    if ($err != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

   

public function VERSION() {
    return secureblackbox_samlreader_get($this->handle, 0);
  }
 /**
  * An accessor to the EndpointIndex entry of the artifact.
  *
  * @access   public
  */
  public function getArtifactEndpointIndex() {
    return secureblackbox_samlreader_get($this->handle, 1 );
  }


 /**
  * An accessor to the MessageHandle property of the artifact.
  *
  * @access   public
  */
  public function getArtifactMessageHandle() {
    return secureblackbox_samlreader_get($this->handle, 2 );
  }


 /**
  * Returns the contents of the artifact.
  *
  * @access   public
  */
  public function getArtifactRemainingArtifact() {
    return secureblackbox_samlreader_get($this->handle, 3 );
  }


 /**
  * An accessor to the SourceID property of the artifact.
  *
  * @access   public
  */
  public function getArtifactSourceID() {
    return secureblackbox_samlreader_get($this->handle, 4 );
  }


 /**
  * The TypeCode property of the artifact.
  *
  * @access   public
  */
  public function getArtifactTypeCode() {
    return secureblackbox_samlreader_get($this->handle, 5 );
  }


 /**
  * An accessor to the URI property of the artifact.
  *
  * @access   public
  */
  public function getArtifactURI() {
    return secureblackbox_samlreader_get($this->handle, 6 );
  }


 /**
  * Returns the content of the ArtifactResolve query.
  *
  * @access   public
  */
  public function getArtifactResolveQuery() {
    return secureblackbox_samlreader_get($this->handle, 7 );
  }


 /**
  * Returns the number of assertions in the SAML message.
  *
  * @access   public
  */
  public function getAssertionCount() {
    return secureblackbox_samlreader_get($this->handle, 8 );
  }


 /**
  * Contains the References entry of the SAML assertion ID request.
  *
  * @access   public
  */
  public function getAssertionIDRequestReferences() {
    return secureblackbox_samlreader_get($this->handle, 9 );
  }


 /**
  * The number of records in the AttrQueryAttr arrays.
  *
  * @access   public
  */
  public function getAttrQueryAttrCount() {
    return secureblackbox_samlreader_get($this->handle, 10 );
  }


 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  */
  public function getAttrQueryAttrFriendlyName($attrqueryattrindex) {
    return secureblackbox_samlreader_get($this->handle, 11 , $attrqueryattrindex);
  }


 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  */
  public function getAttrQueryAttrName($attrqueryattrindex) {
    return secureblackbox_samlreader_get($this->handle, 12 , $attrqueryattrindex);
  }


 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  */
  public function getAttrQueryAttrNameFormat($attrqueryattrindex) {
    return secureblackbox_samlreader_get($this->handle, 13 , $attrqueryattrindex);
  }


 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  */
  public function getAttrQueryAttrStatementIndex($attrqueryattrindex) {
    return secureblackbox_samlreader_get($this->handle, 14 , $attrqueryattrindex);
  }


 /**
  * Contains a list of attribute values.
  *
  * @access   public
  */
  public function getAttrQueryAttrValues($attrqueryattrindex) {
    return secureblackbox_samlreader_get($this->handle, 15 , $attrqueryattrindex);
  }


 /**
  * Specifies the authentication context comparison method.
  *
  * @access   public
  */
  public function getAuthnQueryComparison() {
    return secureblackbox_samlreader_get($this->handle, 16 );
  }


 /**
  * Specifies the context class reference.
  *
  * @access   public
  */
  public function getAuthnQueryContextClassRefs() {
    return secureblackbox_samlreader_get($this->handle, 17 );
  }


 /**
  * Specifies the context reference type.
  *
  * @access   public
  */
  public function getAuthnQueryRefType() {
    return secureblackbox_samlreader_get($this->handle, 18 );
  }


 /**
  * Specifies the index of the session to the authentication entity.
  *
  * @access   public
  */
  public function getAuthnQuerySessionIndex() {
    return secureblackbox_samlreader_get($this->handle, 19 );
  }


 /**
  * Specifies the assertion consumer service index.
  *
  * @access   public
  */
  public function getAuthnRequestAssertionConsumerServiceIndex() {
    return secureblackbox_samlreader_get($this->handle, 20 );
  }


 /**
  * Specifies the assertion consumer service URL.
  *
  * @access   public
  */
  public function getAuthnRequestAssertionConsumerServiceURL() {
    return secureblackbox_samlreader_get($this->handle, 21 );
  }


 /**
  * Specifies the attribute consuming service index.
  *
  * @access   public
  */
  public function getAuthnRequestAttributeConsumingServiceIndex() {
    return secureblackbox_samlreader_get($this->handle, 22 );
  }


 /**
  * Specifies the NotBefore condition of the request.
  *
  * @access   public
  */
  public function getAuthnRequestConditionsNotBefore() {
    return secureblackbox_samlreader_get($this->handle, 23 );
  }


 /**
  * Provides access to the NotOnOrAfter condition of the request.
  *
  * @access   public
  */
  public function getAuthnRequestConditionsNotOnOrAfter() {
    return secureblackbox_samlreader_get($this->handle, 24 );
  }


 /**
  * Provides access to the authentication context class references.
  *
  * @access   public
  */
  public function getAuthnRequestContextClassRefs() {
    return secureblackbox_samlreader_get($this->handle, 25 );
  }


 /**
  * Specifies the AuthnContext comparison method.
  *
  * @access   public
  */
  public function getAuthnRequestContextComparison() {
    return secureblackbox_samlreader_get($this->handle, 26 );
  }


 /**
  * Specifies the context reference type.
  *
  * @access   public
  */
  public function getAuthnRequestContextRefType() {
    return secureblackbox_samlreader_get($this->handle, 27 );
  }


 /**
  * Corresponds to the ForceAuthn parameter of the request.
  *
  * @access   public
  */
  public function getAuthnRequestForceAuthn() {
    return secureblackbox_samlreader_get($this->handle, 28 );
  }


 /**
  * Maps to the IsPassive parameter of the request.
  *
  * @access   public
  */
  public function getAuthnRequestIsPassive() {
    return secureblackbox_samlreader_get($this->handle, 29 );
  }


 /**
  * Matches the AllowCreate attribute of NameIDPolicy element of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyAllowCreate() {
    return secureblackbox_samlreader_get($this->handle, 30 );
  }


 /**
  * Matches to the Format attribute of the NameIDPolicy element of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyFormat() {
    return secureblackbox_samlreader_get($this->handle, 31 );
  }


 /**
  * Matches to the SP name qualifier attribute of the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicySPNameQualifier() {
    return secureblackbox_samlreader_get($this->handle, 32 );
  }


 /**
  * Controls inclusion of AllowCreate attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestNameIDPolicyUseAllowCreate() {
    return secureblackbox_samlreader_get($this->handle, 33 );
  }


 /**
  * Specifies the protocol binding to be requested in the authentication request.
  *
  * @access   public
  */
  public function getAuthnRequestProtocolBinding() {
    return secureblackbox_samlreader_get($this->handle, 34 );
  }


 /**
  * Specifies the name of the requestor.
  *
  * @access   public
  */
  public function getAuthnRequestProviderName() {
    return secureblackbox_samlreader_get($this->handle, 35 );
  }


 /**
  * Matches the GetComplete element of the IDPList entry of the Scoping object.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPListGetComplete() {
    return secureblackbox_samlreader_get($this->handle, 36 );
  }


 /**
  * The maximum number of proxies on the way between the requestor and the provider.
  *
  * @access   public
  */
  public function getAuthnRequestScopingProxyCount() {
    return secureblackbox_samlreader_get($this->handle, 37 );
  }


 /**
  * A collection of requestor IDs on whose behalf the request is being sent.
  *
  * @access   public
  */
  public function getAuthnRequestScopingRequesterIDs() {
    return secureblackbox_samlreader_get($this->handle, 38 );
  }


 /**
  * Controls inclusion of ForceAuthn attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestUseForceAuthn() {
    return secureblackbox_samlreader_get($this->handle, 39 );
  }


 /**
  * Controls inclusion of IsPassive attribute in the request.
  *
  * @access   public
  */
  public function getAuthnRequestUseIsPassive() {
    return secureblackbox_samlreader_get($this->handle, 40 );
  }


 /**
  * The number of records in the AuthnRequestCondition arrays.
  *
  * @access   public
  */
  public function getAuthnRequestConditionCount() {
    return secureblackbox_samlreader_get($this->handle, 41 );
  }


 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  */
  public function getAuthnRequestConditionAudienceList($authnrequestconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 42 , $authnrequestconditionindex);
  }


 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  */
  public function getAuthnRequestConditionConditionType($authnrequestconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 43 , $authnrequestconditionindex);
  }


 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  */
  public function getAuthnRequestConditionProxyRestrictionCount($authnrequestconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 44 , $authnrequestconditionindex);
  }


 /**
  * The number of records in the AuthnRequestScopingIDP arrays.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPCount() {
    return secureblackbox_samlreader_get($this->handle, 45 );
  }


 /**
  * Contains the value of the Loc attribute.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPLoc($authnrequestscopingidpindex) {
    return secureblackbox_samlreader_get($this->handle, 46 , $authnrequestscopingidpindex);
  }


 /**
  * Contains the name of the IdP provider.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPName($authnrequestscopingidpindex) {
    return secureblackbox_samlreader_get($this->handle, 47 , $authnrequestscopingidpindex);
  }


 /**
  * Contains the provider ID.
  *
  * @access   public
  */
  public function getAuthnRequestScopingIDPProviderID($authnrequestscopingidpindex) {
    return secureblackbox_samlreader_get($this->handle, 48 , $authnrequestscopingidpindex);
  }


 /**
  * Specifies the list of actions included in the query.
  *
  * @access   public
  */
  public function getAuthzDecisionQueryActions() {
    return secureblackbox_samlreader_get($this->handle, 49 );
  }


 /**
  * Matches the Resource element of the query.
  *
  * @access   public
  */
  public function getAuthzDecisionQueryResource() {
    return secureblackbox_samlreader_get($this->handle, 50 );
  }


 /**
  * Returns the SAML message binding type.
  *
  * @access   public
  */
  public function getBinding() {
    return secureblackbox_samlreader_get($this->handle, 51 );
  }


 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  */
  public function getBlockedCertCount() {
    return secureblackbox_samlreader_get($this->handle, 52 );
  }
 /**
  * The number of records in the BlockedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setBlockedCertCount($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 52, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getBlockedCertBytes($blockedcertindex) {
    return secureblackbox_samlreader_get($this->handle, 53 , $blockedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getBlockedCertHandle($blockedcertindex) {
    return secureblackbox_samlreader_get($this->handle, 54 , $blockedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setBlockedCertHandle($blockedcertindex, $value) {
    $ret = secureblackbox_samlreader_set($this->handle, 54, $value , $blockedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getChainValidationDetails() {
    return secureblackbox_samlreader_get($this->handle, 55 );
  }


 /**
  * The general outcome of a certificate chain validation routine. Use ChainValidationDetails to get information about the reasons that contributed to the validation result.
  *
  * @access   public
  */
  public function getChainValidationResult() {
    return secureblackbox_samlreader_get($this->handle, 56 );
  }


 /**
  * Returns the Consent parameter of the SAML message.
  *
  * @access   public
  */
  public function getConsent() {
    return secureblackbox_samlreader_get($this->handle, 57 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getDecryptionCertificateBytes() {
    return secureblackbox_samlreader_get($this->handle, 58 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getDecryptionCertificateHandle() {
    return secureblackbox_samlreader_get($this->handle, 59 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setDecryptionCertificateHandle($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 59, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the Destination parameter of the SAML message.
  *
  * @access   public
  */
  public function getDestination() {
    return secureblackbox_samlreader_get($this->handle, 60 );
  }


 /**
  * Returns the ID of the processed message.
  *
  * @access   public
  */
  public function getID() {
    return secureblackbox_samlreader_get($this->handle, 61 );
  }


 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  */
  public function getIgnoreChainValidationErrors() {
    return secureblackbox_samlreader_get($this->handle, 62 );
  }
 /**
  * Makes the class tolerant to chain validation errors.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setIgnoreChainValidationErrors($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 62, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns the type of the processed message.
  *
  * @access   public
  */
  public function getInputType() {
    return secureblackbox_samlreader_get($this->handle, 63 );
  }


 /**
  * Returns the type of the processed message, as an original string.
  *
  * @access   public
  */
  public function getInputTypeString() {
    return secureblackbox_samlreader_get($this->handle, 64 );
  }


 /**
  * Returns the in-response-to parameter of the message.
  *
  * @access   public
  */
  public function getInResponseTo() {
    return secureblackbox_samlreader_get($this->handle, 65 );
  }


 /**
  * Returns the issue time of the message.
  *
  * @access   public
  */
  public function getIssueInstant() {
    return secureblackbox_samlreader_get($this->handle, 66 );
  }


 /**
  * Returns the issuer of the message.
  *
  * @access   public
  */
  public function getIssuer() {
    return secureblackbox_samlreader_get($this->handle, 67 );
  }


 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  */
  public function getKnownCertCount() {
    return secureblackbox_samlreader_get($this->handle, 68 );
  }
 /**
  * The number of records in the KnownCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCertCount($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 68, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getKnownCertBytes($knowncertindex) {
    return secureblackbox_samlreader_get($this->handle, 69 , $knowncertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCertHandle($knowncertindex) {
    return secureblackbox_samlreader_get($this->handle, 70 , $knowncertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCertHandle($knowncertindex, $value) {
    $ret = secureblackbox_samlreader_set($this->handle, 70, $value , $knowncertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  */
  public function getKnownCRLCount() {
    return secureblackbox_samlreader_get($this->handle, 71 );
  }
 /**
  * The number of records in the KnownCRL arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownCRLCount($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 71, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw CRL data in DER format.
  *
  * @access   public
  */
  public function getKnownCRLBytes($knowncrlindex) {
    return secureblackbox_samlreader_get($this->handle, 72 , $knowncrlindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownCRLHandle($knowncrlindex) {
    return secureblackbox_samlreader_get($this->handle, 73 , $knowncrlindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownCRLHandle($knowncrlindex, $value) {
    $ret = secureblackbox_samlreader_set($this->handle, 73, $value , $knowncrlindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  */
  public function getKnownOCSPCount() {
    return secureblackbox_samlreader_get($this->handle, 74 );
  }
 /**
  * The number of records in the KnownOCSP arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setKnownOCSPCount($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 74, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Buffer containing raw OCSP response data.
  *
  * @access   public
  */
  public function getKnownOCSPBytes($knownocspindex) {
    return secureblackbox_samlreader_get($this->handle, 75 , $knownocspindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getKnownOCSPHandle($knownocspindex) {
    return secureblackbox_samlreader_get($this->handle, 76 , $knownocspindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setKnownOCSPHandle($knownocspindex, $value) {
    $ret = secureblackbox_samlreader_set($this->handle, 76, $value , $knownocspindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the value of the NameID parameter.
  *
  * @access   public
  */
  public function getLogoutRequestNameID() {
    return secureblackbox_samlreader_get($this->handle, 77 );
  }


 /**
  * Contains the value of the NotOnOrAfter parameter.
  *
  * @access   public
  */
  public function getLogoutRequestNotOnOrAfter() {
    return secureblackbox_samlreader_get($this->handle, 78 );
  }


 /**
  * Contains the value of the Reason parameter.
  *
  * @access   public
  */
  public function getLogoutRequestReason() {
    return secureblackbox_samlreader_get($this->handle, 79 );
  }


 /**
  * Contains the list of session indices.
  *
  * @access   public
  */
  public function getLogoutRequestSessionIndexes() {
    return secureblackbox_samlreader_get($this->handle, 80 );
  }


 /**
  * Contains the value of the NameID parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestNameID() {
    return secureblackbox_samlreader_get($this->handle, 81 );
  }


 /**
  * Contains the value of the NewEncryptedID parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestNewEncryptedID() {
    return secureblackbox_samlreader_get($this->handle, 82 );
  }


 /**
  * Contains the value of the NewID parameter.
  *
  * @access   public
  */
  public function getManageNameIDRequestNewID() {
    return secureblackbox_samlreader_get($this->handle, 83 );
  }


 /**
  * Contains the value of the Terminate parameter of the request.
  *
  * @access   public
  */
  public function getManageNameIDRequestTerminate() {
    return secureblackbox_samlreader_get($this->handle, 84 );
  }


 /**
  * An accessor to the NameID parameter of the request.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameID() {
    return secureblackbox_samlreader_get($this->handle, 85 );
  }


 /**
  * Contains the value of AllowCreate parameter of the NameIDPolicy object.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyAllowCreate() {
    return secureblackbox_samlreader_get($this->handle, 86 );
  }


 /**
  * Specifies the format of the NameIDPolicy element.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyFormat() {
    return secureblackbox_samlreader_get($this->handle, 87 );
  }


 /**
  * Contains the SPNameQualifier parameter of the NameIDPolicy element.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicySPNameQualifier() {
    return secureblackbox_samlreader_get($this->handle, 88 );
  }


 /**
  * Controls inclusion of UseAllow modifier in the NameIDPolicy object.
  *
  * @access   public
  */
  public function getNameIDMappingRequestNameIDPolicyUseAllowCreate() {
    return secureblackbox_samlreader_get($this->handle, 89 );
  }


 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  */
  public function getOfflineMode() {
    return secureblackbox_samlreader_get($this->handle, 90 );
  }
 /**
  * Switches the class to the offline mode.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setOfflineMode($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 90, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the PinnedAssertionAttr arrays.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrCount() {
    return secureblackbox_samlreader_get($this->handle, 91 );
  }


 /**
  * Specifies the friendly name of the attribute Use this property to access or set the friendly name of a SAML attribute (e.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrFriendlyName($pinnedassertionattrindex) {
    return secureblackbox_samlreader_get($this->handle, 92 , $pinnedassertionattrindex);
  }


 /**
  * Specifies the name of the attribute.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrName($pinnedassertionattrindex) {
    return secureblackbox_samlreader_get($this->handle, 93 , $pinnedassertionattrindex);
  }


 /**
  * Indicates the format used to reference the attribute.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrNameFormat($pinnedassertionattrindex) {
    return secureblackbox_samlreader_get($this->handle, 94 , $pinnedassertionattrindex);
  }


 /**
  * Contains the index of the statement the attribute corresponds to.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrStatementIndex($pinnedassertionattrindex) {
    return secureblackbox_samlreader_get($this->handle, 95 , $pinnedassertionattrindex);
  }


 /**
  * Contains a list of attribute values.
  *
  * @access   public
  */
  public function getPinnedAssertionAttrValues($pinnedassertionattrindex) {
    return secureblackbox_samlreader_get($this->handle, 96 , $pinnedassertionattrindex);
  }


 /**
  * The number of records in the PinnedAssertionCondition arrays.
  *
  * @access   public
  */
  public function getPinnedAssertionConditionCount() {
    return secureblackbox_samlreader_get($this->handle, 97 );
  }


 /**
  * An accessor to the Audience list parameter of an audience restriction condition.
  *
  * @access   public
  */
  public function getPinnedAssertionConditionAudienceList($pinnedassertionconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 98 , $pinnedassertionconditionindex);
  }


 /**
  * Specifies a type of the condition object.
  *
  * @access   public
  */
  public function getPinnedAssertionConditionConditionType($pinnedassertionconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 99 , $pinnedassertionconditionindex);
  }


 /**
  * An accessor to the proxy restriction count element of the condition.
  *
  * @access   public
  */
  public function getPinnedAssertionConditionProxyRestrictionCount($pinnedassertionconditionindex) {
    return secureblackbox_samlreader_get($this->handle, 100 , $pinnedassertionconditionindex);
  }


 /**
  * Contains the number of advice assertions.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoAdviceAssertionCount() {
    return secureblackbox_samlreader_get($this->handle, 101 );
  }


 /**
  * Specifies the type of the assertion.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoAssertionType() {
    return secureblackbox_samlreader_get($this->handle, 102 );
  }


 /**
  * The details of a certificate chain validation outcome.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoChainValidationDetails() {
    return secureblackbox_samlreader_get($this->handle, 103 );
  }


 /**
  * The outcome of a certificate chain validation routine.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoChainValidationResult() {
    return secureblackbox_samlreader_get($this->handle, 104 );
  }


 /**
  * Represents the Conditions.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoConditionsNotBefore() {
    return secureblackbox_samlreader_get($this->handle, 105 );
  }


 /**
  * Represents the Conditions.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoConditionsNotOnOrAfter() {
    return secureblackbox_samlreader_get($this->handle, 106 );
  }


 /**
  * Represents the encrypted assertion content.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoEncryptedContent() {
    return secureblackbox_samlreader_get($this->handle, 107 );
  }


 /**
  * Represents the ID of the assertion.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoID() {
    return secureblackbox_samlreader_get($this->handle, 108 );
  }


 /**
  * Represents an ID reference value.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoIDRef() {
    return secureblackbox_samlreader_get($this->handle, 109 );
  }


 /**
  * Contains the assertion issuance time stamp.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoIssueInstant() {
    return secureblackbox_samlreader_get($this->handle, 110 );
  }


 /**
  * The outcome of the cryptographic signature validation.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoSignatureValidationResult() {
    return secureblackbox_samlreader_get($this->handle, 111 );
  }


 /**
  * Specifies whether the assertion is signed.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoSigned() {
    return secureblackbox_samlreader_get($this->handle, 112 );
  }


 /**
  * Represents an URI reference value.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoURIRef() {
    return secureblackbox_samlreader_get($this->handle, 113 );
  }


 /**
  * Contains the signing certificate's chain validation log.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoValidationLog() {
    return secureblackbox_samlreader_get($this->handle, 114 );
  }


 /**
  * Specifies the SAML protocol version used.
  *
  * @access   public
  */
  public function getPinnedAssertionInfoVersion() {
    return secureblackbox_samlreader_get($this->handle, 115 );
  }


 /**
  * Returns the pinned assertion issuer.
  *
  * @access   public
  */
  public function getPinnedAssertionIssuer() {
    return secureblackbox_samlreader_get($this->handle, 116 );
  }


 /**
  * The number of records in the PinnedAssertionStatement arrays.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementCount() {
    return secureblackbox_samlreader_get($this->handle, 117 );
  }


 /**
  * Contains a list of statement attribute names.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAttributes($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 118 , $pinnedassertionstatementindex);
  }


 /**
  * Contains the list of authenticating authorities.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnContextAuthenticatingAuthorities($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 119 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authentication context choice variant.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnContextChoice($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 120 , $pinnedassertionstatementindex);
  }


 /**
  * Indicates the authentication contexts class reference.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnContextClassRef($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 121 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authentication contexts declaration.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnContextDecl($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 122 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authentication contexts declaration reference.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnContextDeclRef($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 123 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authentication event timestamp.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnInstant($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 124 , $pinnedassertionstatementindex);
  }


 /**
  * Contains the authentication session index.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnSessionIndex($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 125 , $pinnedassertionstatementindex);
  }


 /**
  * Maps to the SessionNotOnOrAfter parameter of the authentication statement.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnSessionNotOnOrAfter($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 126 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authentication subjects address.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnSubjectLocalityAddress($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 127 , $pinnedassertionstatementindex);
  }


 /**
  * Maps to the authentication subjects DNS name parameter.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthnSubjectLocalityDNSName($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 128 , $pinnedassertionstatementindex);
  }


 /**
  * Provides access to the list of actions of the authorization statement.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthzActions($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 129 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authorization decision.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthzDecision($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 130 , $pinnedassertionstatementindex);
  }


 /**
  * Manages the authorization decision statement evidence parameter.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthzDecisionEvidence($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 131 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the authorization decision statement resource parameter.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementAuthzDecisionResource($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 132 , $pinnedassertionstatementindex);
  }


 /**
  * Specifies the assertion statement type.
  *
  * @access   public
  */
  public function getPinnedAssertionStatementStatementType($pinnedassertionstatementindex) {
    return secureblackbox_samlreader_get($this->handle, 133 , $pinnedassertionstatementindex);
  }


 /**
  * The number of records in the PinnedAssertionSubjectConfirmation arrays.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationCount() {
    return secureblackbox_samlreader_get($this->handle, 134 );
  }


 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataAddress($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 135 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataInResponseTo($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 136 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataNotBefore($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 137 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataNotOnOrAfter($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 138 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataRecipient($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 139 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationDataType($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 140 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationID($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 141 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectConfirmationMethod($pinnedassertionsubjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 142 , $pinnedassertionsubjectconfirmationindex);
  }


 /**
  * Returns the pinned assertion subject.
  *
  * @access   public
  */
  public function getPinnedAssertionSubjectID() {
    return secureblackbox_samlreader_get($this->handle, 143 );
  }


 /**
  * Contains the form body.
  *
  * @access   public
  */
  public function getPOSTBindingBody() {
    return secureblackbox_samlreader_get($this->handle, 144 );
  }


 /**
  * Contains the XHTML form template returned by the service provider.
  *
  * @access   public
  */
  public function getPOSTBindingFormTemplate() {
    return secureblackbox_samlreader_get($this->handle, 145 );
  }


 /**
  * Specifies whether binding is applied on a server, or on a client side.
  *
  * @access   public
  */
  public function getPOSTBindingMode() {
    return secureblackbox_samlreader_get($this->handle, 146 );
  }


 /**
  * Contains the value of the RelayState parameter of POST binding mechanism.
  *
  * @access   public
  */
  public function getPOSTBindingRelayState() {
    return secureblackbox_samlreader_get($this->handle, 147 );
  }


 /**
  * Contains the URL of POST binding mechanism.
  *
  * @access   public
  */
  public function getPOSTBindingURL() {
    return secureblackbox_samlreader_get($this->handle, 148 );
  }


 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  */
  public function getProfile() {
    return secureblackbox_samlreader_get($this->handle, 149 );
  }
 /**
  * Specifies a pre-defined profile to apply when creating the signature.
  *
  * @access   public
  * @param    string   value
  */
  public function setProfile($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 149, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The IP address of the proxy server.
  *
  * @access   public
  */
  public function getProxyAddress() {
    return secureblackbox_samlreader_get($this->handle, 150 );
  }
 /**
  * The IP address of the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyAddress($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 150, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  */
  public function getProxyAuthentication() {
    return secureblackbox_samlreader_get($this->handle, 151 );
  }
 /**
  * The authentication type used by the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyAuthentication($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 151, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  */
  public function getProxyPassword() {
    return secureblackbox_samlreader_get($this->handle, 152 );
  }
 /**
  * The password to authenticate to the proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyPassword($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 152, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  */
  public function getProxyPort() {
    return secureblackbox_samlreader_get($this->handle, 153 );
  }
 /**
  * The port on the proxy server to connect to.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyPort($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 153, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The type of the proxy server.
  *
  * @access   public
  */
  public function getProxyProxyType() {
    return secureblackbox_samlreader_get($this->handle, 154 );
  }
 /**
  * The type of the proxy server.
  *
  * @access   public
  * @param    int   value
  */
  public function setProxyProxyType($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 154, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  */
  public function getProxyRequestHeaders() {
    return secureblackbox_samlreader_get($this->handle, 155 );
  }
 /**
  * Contains HTTP request headers for WebTunnel and HTTP proxy.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyRequestHeaders($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 155, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  */
  public function getProxyResponseBody() {
    return secureblackbox_samlreader_get($this->handle, 156 );
  }
 /**
  * Contains the HTTP or HTTPS (WebTunnel) proxy response body.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseBody($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 156, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  */
  public function getProxyResponseHeaders() {
    return secureblackbox_samlreader_get($this->handle, 157 );
  }
 /**
  * Contains response headers received from an HTTP or HTTPS (WebTunnel) proxy server.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyResponseHeaders($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 157, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  */
  public function getProxyUseIPv6() {
    return secureblackbox_samlreader_get($this->handle, 158 );
  }
 /**
  * Specifies whether IPv6 should be used when connecting through the proxy.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseIPv6($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 158, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  */
  public function getProxyUseProxy() {
    return secureblackbox_samlreader_get($this->handle, 159 );
  }
 /**
  * Enables or disables proxy-driven connection.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setProxyUseProxy($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 159, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  */
  public function getProxyUsername() {
    return secureblackbox_samlreader_get($this->handle, 160 );
  }
 /**
  * Specifies the username credential for proxy authentication.
  *
  * @access   public
  * @param    string   value
  */
  public function setProxyUsername($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 160, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the message encoding.
  *
  * @access   public
  */
  public function getRedirectBindingEncoding() {
    return secureblackbox_samlreader_get($this->handle, 161 );
  }


 /**
  * Enforces a signature over all outgoing messages.
  *
  * @access   public
  */
  public function getRedirectBindingForceSign() {
    return secureblackbox_samlreader_get($this->handle, 162 );
  }


 /**
  * Contains the RelayState parameter of the binding.
  *
  * @access   public
  */
  public function getRedirectBindingRelayState() {
    return secureblackbox_samlreader_get($this->handle, 163 );
  }


 /**
  * Specifies whether to sign generated messages.
  *
  * @access   public
  */
  public function getRedirectBindingSign() {
    return secureblackbox_samlreader_get($this->handle, 164 );
  }


 /**
  * Contains the signature algorithm.
  *
  * @access   public
  */
  public function getRedirectBindingSignatureAlgorithm() {
    return secureblackbox_samlreader_get($this->handle, 165 );
  }


 /**
  * Contains the URL of the request query.
  *
  * @access   public
  */
  public function getRedirectBindingURL() {
    return secureblackbox_samlreader_get($this->handle, 166 );
  }


 /**
  * Instructs the class whether to verify incoming signatures.
  *
  * @access   public
  */
  public function getRedirectBindingVerifySignatures() {
    return secureblackbox_samlreader_get($this->handle, 167 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getRedirectBindingCertBytes() {
    return secureblackbox_samlreader_get($this->handle, 168 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getRedirectBindingCertHandle() {
    return secureblackbox_samlreader_get($this->handle, 169 );
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setRedirectBindingCertHandle($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 169, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the NameID parameter of a NameIDMapping response.
  *
  * @access   public
  */
  public function getResponseNameID() {
    return secureblackbox_samlreader_get($this->handle, 170 );
  }


 /**
  * An optional message element to be returned with the response.
  *
  * @access   public
  */
  public function getResponseOptionalElement() {
    return secureblackbox_samlreader_get($this->handle, 171 );
  }


 /**
  * Contains the type of the response.
  *
  * @access   public
  */
  public function getResponseResponseType() {
    return secureblackbox_samlreader_get($this->handle, 172 );
  }


 /**
  * The value of the nested StatusCode.
  *
  * @access   public
  */
  public function getResponseStatusCodeSubValue() {
    return secureblackbox_samlreader_get($this->handle, 173 );
  }


 /**
  * Contains the status code value.
  *
  * @access   public
  */
  public function getResponseStatusCodeValue() {
    return secureblackbox_samlreader_get($this->handle, 174 );
  }


 /**
  * Contains additional information on the status of the request.
  *
  * @access   public
  */
  public function getResponseStatusDetail() {
    return secureblackbox_samlreader_get($this->handle, 175 );
  }


 /**
  * Contains a status message (optional).
  *
  * @access   public
  */
  public function getResponseStatusMessage() {
    return secureblackbox_samlreader_get($this->handle, 176 );
  }


 /**
  * Contains the signature validation result.
  *
  * @access   public
  */
  public function getSignatureValidationResult() {
    return secureblackbox_samlreader_get($this->handle, 177 );
  }


 /**
  * Returns true it the message is signed.
  *
  * @access   public
  */
  public function getSigned() {
    return secureblackbox_samlreader_get($this->handle, 178 );
  }


 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getSigningCertBytes() {
    return secureblackbox_samlreader_get($this->handle, 179 );
  }


 /**
  * Indicates whether the certificate has a CA capability (a setting in BasicConstraints extension).
  *
  * @access   public
  */
  public function getSigningCertCA() {
    return secureblackbox_samlreader_get($this->handle, 180 );
  }


 /**
  * A unique identifier (fingerprint) of the CA certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertCAKeyID() {
    return secureblackbox_samlreader_get($this->handle, 181 );
  }


 /**
  * Locations of the CRL (Certificate Revocation List) distribution points used to check this certificate's validity.
  *
  * @access   public
  */
  public function getSigningCertCRLDistributionPoints() {
    return secureblackbox_samlreader_get($this->handle, 182 );
  }


 /**
  * Specifies the elliptic curve of the EC public key.
  *
  * @access   public
  */
  public function getSigningCertCurve() {
    return secureblackbox_samlreader_get($this->handle, 183 );
  }


 /**
  * Contains the fingerprint (a hash imprint) of this certificate.
  *
  * @access   public
  */
  public function getSigningCertFingerprint() {
    return secureblackbox_samlreader_get($this->handle, 184 );
  }


 /**
  * Contains an associated alias (friendly name) of the certificate.
  *
  * @access   public
  */
  public function getSigningCertFriendlyName() {
    return secureblackbox_samlreader_get($this->handle, 185 );
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getSigningCertHandle() {
    return secureblackbox_samlreader_get($this->handle, 186 );
  }


 /**
  * Specifies the hash algorithm to be used in the operations on the certificate (such as key signing) SB_HASH_ALGORITHM_SHA1 SHA1 SB_HASH_ALGORITHM_SHA224 SHA224 SB_HASH_ALGORITHM_SHA256 SHA256 SB_HASH_ALGORITHM_SHA384 SHA384 SB_HASH_ALGORITHM_SHA512 SHA512 SB_HASH_ALGORITHM_MD2 MD2 SB_HASH_ALGORITHM_MD4 MD4 SB_HASH_ALGORITHM_MD5 MD5 SB_HASH_ALGORITHM_RIPEMD160 RIPEMD160 SB_HASH_ALGORITHM_CRC32 CRC32 SB_HASH_ALGORITHM_SSL3 SSL3 SB_HASH_ALGORITHM_GOST_R3411_1994 GOST1994 SB_HASH_ALGORITHM_WHIRLPOOL WHIRLPOOL SB_HASH_ALGORITHM_POLY1305 POLY1305 SB_HASH_ALGORITHM_SHA3_224 SHA3_224 SB_HASH_ALGORITHM_SHA3_256 SHA3_256 SB_HASH_ALGORITHM_SHA3_384 SHA3_384 SB_HASH_ALGORITHM_SHA3_512 SHA3_512 SB_HASH_ALGORITHM_BLAKE2S_128 BLAKE2S_128 SB_HASH_ALGORITHM_BLAKE2S_160 BLAKE2S_160 SB_HASH_ALGORITHM_BLAKE2S_224 BLAKE2S_224 SB_HASH_ALGORITHM_BLAKE2S_256 BLAKE2S_256 SB_HASH_ALGORITHM_BLAKE2B_160 BLAKE2B_160 SB_HASH_ALGORITHM_BLAKE2B_256 BLAKE2B_256 SB_HASH_ALGORITHM_BLAKE2B_384 BLAKE2B_384 SB_HASH_ALGORITHM_BLAKE2B_512 BLAKE2B_512 SB_HASH_ALGORITHM_SHAKE_128 SHAKE_128 SB_HASH_ALGORITHM_SHAKE_256 SHAKE_256 SB_HASH_ALGORITHM_SHAKE_128_LEN SHAKE_128_LEN SB_HASH_ALGORITHM_SHAKE_256_LEN SHAKE_256_LEN .
  *
  * @access   public
  */
  public function getSigningCertHashAlgorithm() {
    return secureblackbox_samlreader_get($this->handle, 187 );
  }


 /**
  * The common name of the certificate issuer (CA), typically a company name.
  *
  * @access   public
  */
  public function getSigningCertIssuer() {
    return secureblackbox_samlreader_get($this->handle, 188 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate issuer.
  *
  * @access   public
  */
  public function getSigningCertIssuerRDN() {
    return secureblackbox_samlreader_get($this->handle, 189 );
  }


 /**
  * Specifies the public key algorithm of this certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyAlgorithm() {
    return secureblackbox_samlreader_get($this->handle, 190 );
  }


 /**
  * Returns the length of the public key.
  *
  * @access   public
  */
  public function getSigningCertKeyBits() {
    return secureblackbox_samlreader_get($this->handle, 191 );
  }


 /**
  * Returns a fingerprint of the public key contained in the certificate.
  *
  * @access   public
  */
  public function getSigningCertKeyFingerprint() {
    return secureblackbox_samlreader_get($this->handle, 192 );
  }


 /**
  * Indicates the purposes of the key contained in the certificate, in the form of an OR'ed flag set.
  *
  * @access   public
  */
  public function getSigningCertKeyUsage() {
    return secureblackbox_samlreader_get($this->handle, 193 );
  }


 /**
  * Returns True if the certificate's key is cryptographically valid, and False otherwise.
  *
  * @access   public
  */
  public function getSigningCertKeyValid() {
    return secureblackbox_samlreader_get($this->handle, 194 );
  }


 /**
  * Locations of OCSP (Online Certificate Status Protocol) services that can be used to check this certificate's validity, as recorded by the CA.
  *
  * @access   public
  */
  public function getSigningCertOCSPLocations() {
    return secureblackbox_samlreader_get($this->handle, 195 );
  }


 /**
  * Contains identifiers (OIDs) of the applicable certificate policies.
  *
  * @access   public
  */
  public function getSigningCertPolicyIDs() {
    return secureblackbox_samlreader_get($this->handle, 196 );
  }


 /**
  * Contains the certificate's public key in DER format.
  *
  * @access   public
  */
  public function getSigningCertPublicKeyBytes() {
    return secureblackbox_samlreader_get($this->handle, 197 );
  }


 /**
  * Indicates whether the certificate is self-signed (root) or signed by an external CA.
  *
  * @access   public
  */
  public function getSigningCertSelfSigned() {
    return secureblackbox_samlreader_get($this->handle, 198 );
  }


 /**
  * Returns the certificate's serial number.
  *
  * @access   public
  */
  public function getSigningCertSerialNumber() {
    return secureblackbox_samlreader_get($this->handle, 199 );
  }


 /**
  * Indicates the algorithm that was used by the CA to sign this certificate.
  *
  * @access   public
  */
  public function getSigningCertSigAlgorithm() {
    return secureblackbox_samlreader_get($this->handle, 200 );
  }


 /**
  * The common name of the certificate holder, typically an individual's name, a URL, an e-mail address, or a company name.
  *
  * @access   public
  */
  public function getSigningCertSubject() {
    return secureblackbox_samlreader_get($this->handle, 201 );
  }


 /**
  * Contains a unique identifier (fingerprint) of the certificate's private key.
  *
  * @access   public
  */
  public function getSigningCertSubjectKeyID() {
    return secureblackbox_samlreader_get($this->handle, 202 );
  }


 /**
  * A collection of information, in the form of [OID, Value] pairs, uniquely identifying the certificate holder (subject).
  *
  * @access   public
  */
  public function getSigningCertSubjectRDN() {
    return secureblackbox_samlreader_get($this->handle, 203 );
  }


 /**
  * The time point at which the certificate becomes valid, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidFrom() {
    return secureblackbox_samlreader_get($this->handle, 204 );
  }


 /**
  * The time point at which the certificate expires, in UTC.
  *
  * @access   public
  */
  public function getSigningCertValidTo() {
    return secureblackbox_samlreader_get($this->handle, 205 );
  }


 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  */
  public function getSocketDNSMode() {
    return secureblackbox_samlreader_get($this->handle, 206 );
  }
 /**
  * Selects the DNS resolver to use: the class's (secure) built-in one, or the one provided by the system.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSMode($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 206, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  */
  public function getSocketDNSPort() {
    return secureblackbox_samlreader_get($this->handle, 207 );
  }
 /**
  * Specifies the port number to be used for sending queries to the DNS server.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSPort($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 207, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  */
  public function getSocketDNSQueryTimeout() {
    return secureblackbox_samlreader_get($this->handle, 208 );
  }
 /**
  * The timeout (in milliseconds) for each DNS query.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSQueryTimeout($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 208, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  */
  public function getSocketDNSServers() {
    return secureblackbox_samlreader_get($this->handle, 209 );
  }
 /**
  * The addresses of DNS servers to use for address resolution, separated by commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketDNSServers($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 209, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  */
  public function getSocketDNSTotalTimeout() {
    return secureblackbox_samlreader_get($this->handle, 210 );
  }
 /**
  * The timeout (in milliseconds) for the whole resolution process.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketDNSTotalTimeout($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 210, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  */
  public function getSocketIncomingSpeedLimit() {
    return secureblackbox_samlreader_get($this->handle, 211 );
  }
 /**
  * The maximum number of bytes to read from the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketIncomingSpeedLimit($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 211, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalAddress() {
    return secureblackbox_samlreader_get($this->handle, 212 );
  }
 /**
  * The local network interface to bind the socket to.
  *
  * @access   public
  * @param    string   value
  */
  public function setSocketLocalAddress($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 212, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  */
  public function getSocketLocalPort() {
    return secureblackbox_samlreader_get($this->handle, 213 );
  }
 /**
  * The local port number to bind the socket to.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketLocalPort($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 213, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  */
  public function getSocketOutgoingSpeedLimit() {
    return secureblackbox_samlreader_get($this->handle, 214 );
  }
 /**
  * The maximum number of bytes to write to the socket, per second.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketOutgoingSpeedLimit($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 214, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  */
  public function getSocketTimeout() {
    return secureblackbox_samlreader_get($this->handle, 215 );
  }
 /**
  * The maximum period of waiting, in milliseconds, after which the socket operation is considered unsuccessful.
  *
  * @access   public
  * @param    int   value
  */
  public function setSocketTimeout($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 215, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  */
  public function getSocketUseIPv6() {
    return secureblackbox_samlreader_get($this->handle, 216 );
  }
 /**
  * Enables or disables IP protocol version 6.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setSocketUseIPv6($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 216, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the SubjectConfirmation arrays.
  *
  * @access   public
  */
  public function getSubjectConfirmationCount() {
    return secureblackbox_samlreader_get($this->handle, 217 );
  }


 /**
  * Contains the address enabled for presenting assertions.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataAddress($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 218 , $subjectconfirmationindex);
  }


 /**
  * The ID of the SAML message in response to which the assertion is issued.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataInResponseTo($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 219 , $subjectconfirmationindex);
  }


 /**
  * Time moment before which the subject cannot be confirmed.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataNotBefore($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 220 , $subjectconfirmationindex);
  }


 /**
  * Limits the time until which the subject can be confirmed.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataNotOnOrAfter($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 221 , $subjectconfirmationindex);
  }


 /**
  * The URI of the entity or the location of the resource to which the assertion should be presented.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataRecipient($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 222 , $subjectconfirmationindex);
  }


 /**
  * The type of data contained in the confirmation.
  *
  * @access   public
  */
  public function getSubjectConfirmationDataType($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 223 , $subjectconfirmationindex);
  }


 /**
  * The identifier of the entity which can satisfy the subject confirmation requirements.
  *
  * @access   public
  */
  public function getSubjectConfirmationID($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 224 , $subjectconfirmationindex);
  }


 /**
  * Specifies the mechanism to be used to confirm the subject.
  *
  * @access   public
  */
  public function getSubjectConfirmationMethod($subjectconfirmationindex) {
    return secureblackbox_samlreader_get($this->handle, 225 , $subjectconfirmationindex);
  }


 /**
  * Returns the subject of the message.
  *
  * @access   public
  */
  public function getSubjectID() {
    return secureblackbox_samlreader_get($this->handle, 226 );
  }


 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  */
  public function getTLSAutoValidateCertificates() {
    return secureblackbox_samlreader_get($this->handle, 227 );
  }
 /**
  * Specifies whether server-side TLS certificates should be validated automatically using internal validation rules.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSAutoValidateCertificates($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 227, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  */
  public function getTLSBaseConfiguration() {
    return secureblackbox_samlreader_get($this->handle, 228 );
  }
 /**
  * Selects the base configuration for the TLS settings.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSBaseConfiguration($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 228, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  */
  public function getTLSCiphersuites() {
    return secureblackbox_samlreader_get($this->handle, 229 );
  }
 /**
  * A list of ciphersuites separated with commas or semicolons.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSCiphersuites($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 229, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  */
  public function getTLSECCurves() {
    return secureblackbox_samlreader_get($this->handle, 230 );
  }
 /**
  * Defines the elliptic curves to enable.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSECCurves($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 230, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  */
  public function getTLSForceResumeIfDestinationChanges() {
    return secureblackbox_samlreader_get($this->handle, 231 );
  }
 /**
  * Whether to force TLS session resumption when the destination address changes.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSForceResumeIfDestinationChanges($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 231, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  */
  public function getTLSPreSharedIdentity() {
    return secureblackbox_samlreader_get($this->handle, 232 );
  }
 /**
  * Defines the identity used when the PSK (Pre-Shared Key) key-exchange mechanism is negotiated.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedIdentity($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 232, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  */
  public function getTLSPreSharedKey() {
    return secureblackbox_samlreader_get($this->handle, 233 );
  }
 /**
  * Contains the pre-shared for the PSK (Pre-Shared Key) key-exchange mechanism, encoded with base16.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKey($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 233, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  */
  public function getTLSPreSharedKeyCiphersuite() {
    return secureblackbox_samlreader_get($this->handle, 234 );
  }
 /**
  * Defines the ciphersuite used for PSK (Pre-Shared Key) negotiation.
  *
  * @access   public
  * @param    string   value
  */
  public function setTLSPreSharedKeyCiphersuite($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 234, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  */
  public function getTLSRenegotiationAttackPreventionMode() {
    return secureblackbox_samlreader_get($this->handle, 235 );
  }
 /**
  * Selects renegotiation attack prevention mechanism.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRenegotiationAttackPreventionMode($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 235, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  */
  public function getTLSRevocationCheck() {
    return secureblackbox_samlreader_get($this->handle, 236 );
  }
 /**
  * Specifies the kind(s) of revocation check to perform.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSRevocationCheck($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 236, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  */
  public function getTLSSSLOptions() {
    return secureblackbox_samlreader_get($this->handle, 237 );
  }
 /**
  * Various SSL (TLS) protocol options, set of cssloExpectShutdownMessage 0x001 cssloOpenSSLDTLSWorkaround 0x002 cssloDisableKexLengthAlignment 0x004 cssloForceUseOfClientCertHashAlg 0x008 cssloAutoAddServerNameExtension 0x010 cssloAcceptTrustedSRPPrimesOnly 0x020 cssloDisableSignatureAlgorithmsExtension 0x040 cssloIntolerateHigherProtocolVersions 0x080 cssloStickToPrefCertHashAlg 0x100 .
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSSSLOptions($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 237, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  */
  public function getTLSTLSMode() {
    return secureblackbox_samlreader_get($this->handle, 238 );
  }
 /**
  * Specifies the TLS mode to use.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSTLSMode($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 238, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  */
  public function getTLSUseExtendedMasterSecret() {
    return secureblackbox_samlreader_get($this->handle, 239 );
  }
 /**
  * Enables Extended Master Secret Extension, as defined in RFC 7627.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseExtendedMasterSecret($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 239, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  */
  public function getTLSUseSessionResumption() {
    return secureblackbox_samlreader_get($this->handle, 240 );
  }
 /**
  * Enables or disables TLS session resumption capability.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setTLSUseSessionResumption($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 240, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  */
  public function getTLSVersions() {
    return secureblackbox_samlreader_get($this->handle, 241 );
  }
 /**
  * Th SSL/TLS versions to enable by default.
  *
  * @access   public
  * @param    int   value
  */
  public function setTLSVersions($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 241, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  */
  public function getTrustedCertCount() {
    return secureblackbox_samlreader_get($this->handle, 242 );
  }
 /**
  * The number of records in the TrustedCert arrays.
  *
  * @access   public
  * @param    int   value
  */
  public function setTrustedCertCount($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 242, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns raw certificate data in DER format.
  *
  * @access   public
  */
  public function getTrustedCertBytes($trustedcertindex) {
    return secureblackbox_samlreader_get($this->handle, 243 , $trustedcertindex);
  }


 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  */
  public function getTrustedCertHandle($trustedcertindex) {
    return secureblackbox_samlreader_get($this->handle, 244 , $trustedcertindex);
  }
 /**
  * Allows to get or set a 'handle', a unique identifier of the underlying property object.
  *
  * @access   public
  * @param    int64   value
  */
  public function setTrustedCertHandle($trustedcertindex, $value) {
    $ret = secureblackbox_samlreader_set($this->handle, 244, $value , $trustedcertindex);
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables automated binding processing.
  *
  * @access   public
  */
  public function getUseBinding() {
    return secureblackbox_samlreader_get($this->handle, 245 );
  }
 /**
  * Enables or disables automated binding processing.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setUseBinding($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 245, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Enables or disables automated signature validation.
  *
  * @access   public
  */
  public function getValidateSignatures() {
    return secureblackbox_samlreader_get($this->handle, 246 );
  }
 /**
  * Enables or disables automated signature validation.
  *
  * @access   public
  * @param    boolean   value
  */
  public function setValidateSignatures($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 246, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Contains the complete log of the certificate validation routine.
  *
  * @access   public
  */
  public function getValidationLog() {
    return secureblackbox_samlreader_get($this->handle, 247 );
  }


 /**
  * The time point at which chain validity is to be established.
  *
  * @access   public
  */
  public function getValidationMoment() {
    return secureblackbox_samlreader_get($this->handle, 248 );
  }
 /**
  * The time point at which chain validity is to be established.
  *
  * @access   public
  * @param    string   value
  */
  public function setValidationMoment($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 248, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
    }
    return $ret;
  }

 /**
  * Returns SAML content version string.
  *
  * @access   public
  */
  public function getVersion() {
    return secureblackbox_samlreader_get($this->handle, 249 );
  }




  public function getRuntimeLicense() {
    return secureblackbox_samlreader_get($this->handle, 2011 );
  }

  public function setRuntimeLicense($value) {
    $ret = secureblackbox_samlreader_set($this->handle, 2011, $value );
    if ($ret != 0) {
      throw new Exception($ret . ": " . secureblackbox_samlreader_get_last_error($this->handle));
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

 /**
  * Signifies the start of signature validation.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, certfound, validatesignature, validatechain    
  */
  public function fireSignatureFound($param) {
    return $param;
  }

 /**
  * Reports the signature validation result.
  *
  * @access   public
  * @param    array   Array of event parameters: issuerrdn, serialnumber, subjectkeyid, validationresult    
  */
  public function fireSignatureValidated($param) {
    return $param;
  }


}

?>
