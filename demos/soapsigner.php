<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - SOAP Signer</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - SOAP Signer"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>SOAP Signer</h2>
<p>This small example illustrates the signing of SOAP messages with SOAPSigner control.</p>
<a href="seecode.php?soapsigner.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_soapsigner.php');
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
    <h2>SOAP Signing Demo</h2>
    
    <h3>General Options</h3>
    <table>
      <tr><td>Input File:</td><td><input type=text name=inputFile value=""></td></tr>
      <tr><td>Output File:</td><td><input type=text name=outputFile value=""></td></tr>
    </table>
    <br/>
    <br/>

    <b>Signing Options</b><br/>
    <table>
      <tr>
        <td>Signature Type:</td>
        <td>
          <select name="sigType">
            <option value="SOAPSIGNER_SIGNATURETYPE_WSSSIGNATURE">WSS Signature</option>
            <option value="SOAPSIGNER_SIGNATURETYPE_SOAPSIGNATURE">SOAP Signature</option>
          </select>
        </td>
      </tr>
      <tr>
        <td>Hash Algorithm:</td>
        <td>
          <select name="hashAlg">
            <option value=""></option>
            <option value="SHA1">SHA1</option>
            <option value="MD5">MD5</option>
            <option value="SHA256">SHA256</option>
            <option value="SHA384">SHA384</option>
            <option value="SHA512">SHA512</option>
            <option value="RIPEMD160">RIPEMD160</option>
          </select>
        </td>
      </tr>
    </table>
    <label> <input type="checkbox" name="signBody" value="1" size="25"/> Sign Body </label>
    <br/>
    <br/>

    <b>Signing Certificate</b>
    <table>
      <tr><td>Certificate File:</td><td><input type=text name=sCertFile value=""></td></tr>
      <tr><td>Password:</td><td><input type=password name=sCertPass value=""></td></tr>
    </table>
    <br/>
    <br/>

    <input type="submit" value="Sign" />
  </form>
</div><br/>

<?php

function translateSignatureType($sigType){
  switch($sigType){
    case "SOAPSIGNER_SIGNATURETYPE_WSSSIGNATURE":  return SOAPSIGNER_SIGNATURETYPE_WSSSIGNATURE; break;
    case "SOAPSIGNER_SIGNATURETYPE_SOAPSIGNATURE":  return SOAPSIGNER_SIGNATURETYPE_SOAPSIGNATURE; break;
    default: return SOAPSIGNER_SIGNATURETYPE_UNKNOWN; break;
  }
}

  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $soapsigner = new SecureBlackbox_SOAPSigner();
    $certmgr = new SecureBlackBox_CertificateManager();
    
    try {
      // General options
      $soapsigner->setInputFile($_REQUEST['inputFile']);
      $soapsigner->setOutputFile($_REQUEST['outputFile']);
      
      // Signing options
      $certmgr->doImportFromFile($_REQUEST['sCertFile'], $_REQUEST['sCertPass']);
      $soapsigner->setSigningCertHandle($certmgr->getCertHandle());
      
      $soapsigner->setSignatureType(translateSignatureType($_REQUEST['sigType']));
      $hashAlg = $_REQUEST['hashAlg'];
      if (!empty($hashAlg)) {$soapsigner->setHashAlgorithm($hashAlg);}
      if (isset($_REQUEST['signBody']) && (($_REQUEST['signBody'] == 'yes') || ($_REQUEST['signBody'] == '1')))
      {
        $soapsigner->doAddBodyReference("", TRUE);
      }

      $soapsigner->doSign();
      echo "<h2>SOAP message successfully signed</h2>";
    }
    catch (exception $e) {
      echo "<h2>Signing Failure (Details Below)</h2><p>" . $e->getMessage() . "</p>";
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
