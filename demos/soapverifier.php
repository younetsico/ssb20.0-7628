<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - SOAP Verifier</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - SOAP Verifier"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>SOAP Verifier</h2>
<p>Use this example to learn about SOAP signature validation with SOAPVerifier control.</p>
<a href="seecode.php?soapverifier.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_soapverifier.php');
require_once('../include/secureblackbox_const.php');

?>

<style>
table { width: 100% !important; }
td { white-space: nowrap; }
td input { width: 100%; }
td:last-child { width: 100%; }
</style>

<div width="90%">
  <form method=POST>
    <h2>SOAP Verifying Demo</h2>
    
    <b>General Options</b><br/><br/>
    <table>
      <tr><td>Input File:</td><td><input type=text name=inputFile value=""></td></tr>
    </table>

    <br/><br/><b>Validation Options</b><br/><br/>

    <input type=checkbox name="ignoreChainValidationErrors" /><label for=ignoreChainValidationErrors>Ignore chain validation errors</label>
    <input type=checkbox name="forceCompleteChainValidation" /><label for=forceCompleteChainValidation>Force complete chain validation</label>
    <input type=checkbox name="performRevocationCheck" /><label for=performRevocationCheck>Perform revocation check</label>

    <br/><br/><br/>

    <b>Additional Certificates</b>
    <p>Enter the path(s) for any certificate(s), one per line. If a password is required add a semicolon followed by the password (e.g. C:\path\to\my.pfx;password).</p>
    <table>
      <tr><td>Known Certificates:</td><td><textarea style="font-family: Arial, sans-serif; width: 100%" name=knownCerts rows=10></textarea></td></tr>
      <tr><td>Trusted Certificates:</td><td><textarea style="font-family: Arial, sans-serif; width: 100%" name=trustedCerts rows=10></textarea></td></tr>
    </table>

    <input type="submit" value="Verify" />
  </form>
</div><br/>

<?php
  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $soapverifier = new SecureBlackbox_SOAPVerifier();
    $certmgr = new SecureBlackBox_CertificateManager();

    try {
      // General options
      $soapverifier->setInputFile($_REQUEST['inputFile']);

      // Additional options
      $soapverifier->setIgnoreChainValidationErrors(!empty($_REQUEST['ignoreChainValidationErrors']));
      $soapverifier->doConfig("ForceCompleteChainValidation=" . !empty($_REQUEST['forceCompleteChainValidation']));
      $soapverifier->setRevocationCheck(!empty($_REQUEST['performRevocationCheck']) ? 1 : 0);

      // Known certificates
      $certPaths = trim($_REQUEST['knownCerts']);
      if (strlen($certPaths) > 0) {
        $knownCerts = explode("\r\n", $certPaths);
        $soapverifier->setKnownCertCount(count($knownCerts));
        for($x = 0; $x < count($knownCerts); $x++){
          $cert = ""; $pass = "";
          $delimitIdx = strpos($knownCerts[$x], ";");
          if($delimitIdx > 0){
            $cert = substr($knownCerts[$x], 0, $delimitIdx);
            $pass = substr($knownCerts[$x], $delimitIdx+1);
          } else {
            $cert = $knownCerts[$x];
          }
          $certmgr->doImportFromFile($cert, $pass);
          $soapverifier->setKnownCertHandle($x, $certmgr->getCertHandle());
        }
      }

      // Trusted certificates
      $certPaths = trim($_REQUEST['trustedCerts']);
      if (strlen($certPaths) > 0) {
        $trustedCerts = explode("\r\n", $certPaths);
        $soapverifier->setTrustedCertCount(count($trustedCerts));
        for($x = 0; $x < count($trustedCerts); $x++){
          $cert = ""; $pass = "";
          $delimitIdx = strpos($trustedCerts[$x], ";");
          if($delimitIdx > 0){
            $cert = substr($trustedCerts[$x], 0, $delimitIdx);
            $pass = substr($trustedCerts[$x], $delimitIdx+1);
          } else {
            $cert = $trustedCerts[$x];
          }
          $certmgr->doImportFromFile($cert, $pass);
          $soapverifier->setTrustedCertHandle($x, $certmgr->getCertHandle());
        }
      }

      // Verification
      $soapverifier->doVerify();

      switch($soapverifier->getSignatureValidationResult())
      {
        case SOAPVERIFIER_SIGNATUREVALIDATIONRESULT_VALID:  echo "<h2>Signature validated successfully</h2>";  break;
        case SOAPVERIFIER_SIGNATUREVALIDATIONRESULT_CORRUPTED:  echo "<h2>Signature is invalid</h2>";  break;
        case SOAPVERIFIER_SIGNATUREVALIDATIONRESULT_SIGNER_NOT_FOUND:  echo "<h2>Signer not found</h2>";  break;
        case SOAPVERIFIER_SIGNATUREVALIDATIONRESULT_FAILURE:  echo "<h2>Signature verification failed</h2>";  break;
        case SOAPVERIFIER_SIGNATUREVALIDATIONRESULT_REFERENCE_CORRUPTED:  echo "<h2>Signature has invalid references</h2>";  break;
        default: echo "<h2>Unknown</h2>";  break;
      }
    }
    catch (exception $e) {
      echo "<h2>Verification Failure (Details Below)</h2><p>" . $e->getMessage() . "</p>";
    }
  }
?><br/>
<br/>
<br/>
<hr/>
NOTE: These pages are simple demos, and by no means complete applications.  They
are intended to illustrate the usage of the SecureBlackbox objects in a simple,
straightforward way.  What we are hoping to demonstrate is how simple it is to
program with our components.  If you want to know more about them, or if you have
questions, please visit <a href="http://www.nsoftware.com/?demopg-SBPFA" target="_blank">www.nsoftware.com</a> or
contact our technical <a href="http://www.nsoftware.com/support/">support</a>.
<br/>
<br/>
Copyright (c) 2020 /n software inc. - All rights reserved.
<br/>
<br/></div>

<div id="footer">
<center>
SecureBlackbox 2020 - Copyright (c) 2020 /n software inc. - All rights reserved. - For more information, please visit our website at <a href="http://www.nsoftware.com/?demopg-SBPFA" target="_blank">www.nsoftware.com</a>.</center></div>
</body></html>

<?php if ($sendBuffer) ob_end_flush(); else ob_end_clean(); ?>
