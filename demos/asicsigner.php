<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - ASiC Signer</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - ASiC Signer"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>ASiC Signer</h2>
<p>A simple ASiC signer sample created with the ASiCSigner component. Use it to create XAdES-signed, CAdES-signed, and timestamped archives.</p>
<a href="seecode.php?asicsigner.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_asicsigner.php');require_once('../include/secureblackbox_certificatemanager.php');
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
    <h2>ASiC Signing Demo</h2>
    
    <h3>General Options</h3>
    <table>
      <tr><td>Input Files:</td><td><textarea style="font-family: Arial, sans-serif; width: 100%" name=SourceFiles rows=10>Enter files here, one per line</textarea></td></tr>
      <tr><td>Output File:</td><td><input type=text name=outputFile value=""></td></tr>
    </table>
    <br/>
    <br/>

    <h3>Signing Options</h3>
    <b>Signature Level:</b><br />
    <div style="display: inline-block; margin: .25em 0;">
      <select id="sigLevel">
        <option value="BES">BES</option>
        <option value="EPES">EPES</option>
        <option value="T">T</option>
        <option value="C">C</option>
        <option value="XType1">XType1</option>
        <option value="XType2">XType2</option>
        <option value="XLType1">XLType1</option>
        <option value="XLType2">XLType2</option>
        <option value="BaselineB">BaselineB</option>
        <option value="BaselineT">BaselineT</option>
        <option value="BaselineLT">BaselineLT</option>
        <option value="BaselineLTA">BaselineLTA</option>
        <option value="ExtendedBES">ExtendedBES</option>
        <option value="ExtendedEPES">ExtendedEPES</option>
        <option value="ExtendedT">ExtendedT</option>
        <option value="ExtendedC">ExtendedC</option>
        <option value="ExtendedXType1">ExtendedXType1</option>
        <option value="ExtendedXType2">ExtendedXType2</option>
        <option value="ExtendedXLType1">ExtendedXLType1</option>
        <option value="ExtendedXLType2 ">ExtendedXLType2 </option>
        <option value="A">A</option>
        <option value="ExtendedA">ExtendedA</option>
      </select>
    </div><br /><br />
    
    <b>Signature Type</b><br/>
    <div style="display: inline-block; margin: .25em 0;">
      <input type=radio id=sigType1 name=sigType value="CAdES" checked />
      <label for=sigType1>CAdES</label>
      &nbsp;&nbsp;&nbsp;
      <input type=radio id=sigType2 name=sigType value="XAdES" />
      <label for=sigType2>XAdES</label>
      &nbsp;&nbsp;&nbsp;
      <input type=checkbox id="useExtended" name="useExtended" />
      <label for=useExtended>Extended</label>
    </div><br/><br/>
    <b>Signing Certificate</b>
    <table>
      <tr><td>Certificate File:</td><td><input type=text name=sCertFile value=""></td></tr>
      <tr><td>Password:</td><td><input type=password name=sCertPass value=""></td></tr>
    </table>
    
    <h3>Additional Options</h3>
    <b>Policy</b>
    <table>
      <tr><td>Identifier:</td><td><input type=text name=policyIdentifier value=""></td></tr>
      <tr><td>Hash Algorithm:</td><td>
        <select id="policyHashAlgo">
          <option value=""></option>
          <option value="SHA1">SHA1</option>
          <option value="MD5">MD5</option>
          <option value="SHA256">SHA256</option>
          <option value="SHA384">SHA384</option>
          <option value="SHA512">SHA512</option>
          <option value="RIPEMD160">RIPEMD160</option>
        </select>
      </td></tr>
      <tr><td>Hash Value:</td><td><input type=text name=policyHashVal value=""></td></tr>
    </table><br />
    <b>Timestamp</b><br/><br/>
    <input type=checkbox id="useTimestamp" name="useTimestamp" /><label for=useTimestamp>Request a timestamp from TSA server</label>
    <table>
      <tr><td>Timestamp Server:</td><td><input type=text name=timestampServer value=""></td></tr>
    </table>
    <input type="submit" value="Sign" />
  </form>
</div><br/>

<?php
  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $asicsigner = new SecureBlackbox_ASiCSigner();
    $certmgr = new SecureBlackBox_CertificateManager();
    
    try {
      // General options
      $SourceFiles = str_replace("\r\n", ",", $_REQUEST['SourceFiles']);
      $asicsigner->setSourceFiles($SourceFiles);
      $asicsigner->setOutputFile($_REQUEST['outputFile']);
      
      // Signing options
      $certmgr->doImportFromFile($_REQUEST['sCertFile'], $_REQUEST['sCertPass']);
      $asicsigner->setSigningCertHandle($certmgr->getCertHandle());
      
      // Additional options
      $asicsigner->setExtended(!empty($_REQUEST['useExtended']));
      $asicsigner->setPolicyID($_REQUEST['policyIdentifier']);
      $asicsigner->setPolicyHashAlgorithm(!empty($_REQUEST['policyHashAlgo']));
      $asicsigner->setPolicyHash($_REQUEST['policyHashVal']);
      $asicsigner->setTimestampServer($_REQUEST['timestampServer']);
    
      $asicsigner->doSign();
      echo "<h2>Signing Successful</h2>";
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
