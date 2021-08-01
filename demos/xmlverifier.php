<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - XML Verifier</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - XML Verifier"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>XML Verifier</h2>
<p>This sample demonstrates the use of XMLVerifier for validating basic XML signatures. For validations involving certificate chain checks, see XAdESVerifier.</p>
<a href="seecode.php?xmlverifier.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_xmlverifier.php');
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
    <h2>XML Verififcation Demo</h2>

    <h3>General Options</h3>
    <table>
      <tr><td>Input File:</td><td><input type=text name=inputFile value=""></td></tr>
    </table><br />

    <input type=checkbox id="detached" name="detached" /><label for=detached>Detached</label><br />
    
    <table>
      <tr><td>Output/Data File:</td><td><input type=text name=dataFile value=""></td></tr>
    </table><br />

    <p>A certificate is only required if the key was not included with the signature.</p>
    <table>
      <tr><td>Certificate:</td><td><input type=text name=certFile value=""></td></tr>
      <tr><td>Password:</td><td><input type=password name=certPass value=""></td></tr>
    </table><br />

    <input type="submit" value="Verify" />
  </form>
</div><br/>

<?php

class MyXMLVerifier extends SecureBlackbox_XMLVerifier
{
  private $referenceOutput;
  
  function getReferenceOutput(){
    return $this->referenceOutput;
  }
  
  function fireReferenceValidated($param){
    $this->referenceOutput .= "<tr>";
    $this->referenceOutput .= "<td>" . $param['id']                             . "</td>";
    $this->referenceOutput .= "<td>" . $param['uri']                            . "</td>";
    $this->referenceOutput .= "<td>" . $param['reftype']                        . "</td>";
    $this->referenceOutput .= "<td>" . $param['digestvalid'] ? "true" : "false" . "</td>";
    $this->referenceOutput .= "</tr>";  

    return $param;
  }
}

  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $xmlverifier = new MyXMLVerifier();
    $certmgr = new SecureBlackBox_CertificateManager();

    try {
      // General options
      $xmlverifier->setInputFile($_REQUEST['inputFile']);
      
      if(!empty($_REQUEST['detached'])){
        if(strcmp($_REQUEST['dataFile'], "") == 0){
          throw new Exception("A data file must be specified if the signature is detached.");
        }
        $xmlverifier->setDataFile($_REQUEST['dataFile']);
      }

      // Verification
      $xmlverifier->doVerify();
      
      echo "<h2>Verification Successful</h2>";
      echo "<h3>References</h3><br />";
      echo "<table>";
      echo $xmlverifier->getReferenceOutput();
      echo "</table><br />";
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
