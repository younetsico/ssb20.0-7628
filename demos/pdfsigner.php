<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - PDF Signer</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - PDF Signer"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>PDF Signer</h2>
<p>An easy-to-use PDF signing example. Both generic and PAdES signatures are supported.</p>
<a href="seecode.php?pdfsigner.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_pdfsigner.php');
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
    <h2>PDF Signing Demo</h2>
    
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
        <td>Level:</td>
        <td>
          <select name="level">
            <option value="PDFSIGNER_SIGLEVEL_LEGACY">Legacy</option>
            <option value="PDFSIGNER_SIGLEVEL_BES">BES</option>
            <option value="PDFSIGNER_SIGLEVEL_EPES">EPES</option>
            <option value="PDFSIGNER_SIGLEVEL_LTV">LTV</option>
            <option value="PDFSIGNER_SIGLEVEL_DOCUMENT_TIMESTAMP">DocumentTimestamp</option>
          </select>
        </td>
      </tr>
    </table>
    <label> <input type="checkbox" name="visible" value="1" size="25"/> Visible signature </label>
    <br/>
    <br/>

    <b>Signing Certificate</b>
    <table>
      <tr><td>Certificate File:</td><td><input type=text name=sCertFile value=""></td></tr>
      <tr><td>Password:</td><td><input type=password name=sCertPass value=""></td></tr>
    </table>
    <br/>
    <br/>

    <input type=checkbox name="autocollectmissrevInfo" /><label for=autocollectmissrevInfo>Automatically collect missing revocation information</label>
    <input type=checkbox name="ignoreChainValidationErrors" /><label for=ignoreChainValidationErrors>Ignore chain validation errors</label>
    <input type=checkbox name="forceCompleteChainValidation" /><label for=forceCompleteChainValidation>Force complete chain validation</label>
    <input type=checkbox name="deepValidation" /><label for=deepValidation>Deep validation</label>
    <br/>
    <br/>
    
    <b>Timestamp</b><br/><br/>
    <label> <input type="checkbox" name="useTimestamp" value="1" size="25"/> Request a timestamp from TSA server </label>
    <table>
      <tr><td>Timestamp Server:</td><td><input type=text name=timestampServer value=""></td></tr>
    </table>
    <br/>
    <br/>

    <input type="submit" value="Sign" />
  </form>
</div><br/>

<?php

function translatePDFLevel($level){
  switch($level){
    case "PDFSIGNER_SIGLEVEL_LEGACY":  return PDFSIGNER_SIGLEVEL_LEGACY; break;
    case "PDFSIGNER_SIGLEVEL_BES":  return PDFSIGNER_SIGLEVEL_BES; break;
    case "PDFSIGNER_SIGLEVEL_EPES":  return PDFSIGNER_SIGLEVEL_EPES; break;
    case "PDFSIGNER_SIGLEVEL_LTV":  return PDFSIGNER_SIGLEVEL_LTV; break;
    case "PDFSIGNER_SIGLEVEL_DOCUMENT_TIMESTAMP":  return PDFSIGNER_SIGLEVEL_DOCUMENT_TIMESTAMP; break;
    default: return PDFSIGNER_SIGLEVEL_LEGACY; break;
  }
}

  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $pdfsigner = new SecureBlackbox_PDFSigner();
    $certmgr = new SecureBlackBox_CertificateManager();
    
    try {
      // General options
      $pdfsigner->setInputFile($_REQUEST['inputFile']);
      $pdfsigner->setOutputFile($_REQUEST['outputFile']);
      
      // Signing options
      $certmgr->doImportFromFile($_REQUEST['sCertFile'], $_REQUEST['sCertPass']);
      $pdfsigner->setSigningCertHandle($certmgr->getCertHandle());
      
      $pdfsigner->setSigLevel(translatePDFLevel($_REQUEST['level']));
      $visible = (isset($_REQUEST['visible']) && (($_REQUEST['visible'] == 'yes') || ($_REQUEST['visible'] == '1')));
      $pdfsigner->setSigInvisible(!$visible);

      $pdfsigner->doConfig("AutoCollectRevocationInfo=" . !empty($_REQUEST['autocollectmissrevInfo']));
      $pdfsigner->setIgnoreChainValidationErrors(!empty($_REQUEST['ignoreChainValidationErrors']));
      $pdfsigner->doConfig("ForceCompleteChainValidation=" . !empty($_REQUEST['forceCompleteChainValidation']));
      $pdfsigner->doConfig("DeepValidation=" . !empty($_REQUEST['deepValidation']));

      if (isset($_REQUEST['useTimestamp']) && (($_REQUEST['useTimestamp'] == 'yes') || ($_REQUEST['useTimestamp'] == '1')))
      {
        $pdfsigner->setTimestampServer($_REQUEST['timestampServer']);
      }

      $pdfsigner->doSign();
      echo "<h2>PDF file successfully signed</h2>";
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
