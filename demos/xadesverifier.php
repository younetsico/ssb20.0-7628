<?php $sendBuffer = TRUE; ob_start(); ?>
<html>
<head>
<title>SecureBlackbox 2020 Demos - XAdES Verifier</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - XAdES Verifier"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2>XAdES Verifier</h2>
<p>This small demo illustrates the use of XAdESVerifier for XAdES signature validations.</p>
<a href="seecode.php?xadesverifier.php">[See The Code]</a>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<?php
require_once('../include/secureblackbox_xadesverifier.php');require_once('../include/secureblackbox_certificatemanager.php');
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
    <h2>XAdES Verififcation Demo</h2>

    <h3>General Options</h3>
    <table>
      <tr><td>Input File:</td><td><input type=text name=inputFile value=""></td></tr>
    </table><br />

    <input type=checkbox id="detached" name="detached" /><label for=detached>Detached</label><br />
    
    <table>
      <tr><td>Data File:</td><td><input type=text name=dataFile value=""></td></tr>
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

class MyXAdESVerifier extends SecureBlackbox_XAdESVerifier
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
  
  function getXAdESVersionAsString() {
    switch($this->getXAdESVersion()) {
      case 1:  return "XAdES v1.1.1";              break;
      case 2:  return "XAdES v1.2.2";              break;
      case 3:  return "XAdES v1.3.2";              break;
      case 4:  return "XAdES v1.4.1 (aka v1.4.2)"; break;
      default: return "Unknown";                   break;
    }
  }
  
  function getXAdESFormAsString(){
    switch($this->getXAdESForm()){
      case 1:  return "XAdES form, supported by XAdES v1.1.1";                 break;
      case 2:  return "XAdES-BES form, supported starting from XAdES v1.2.2";  break;
      case 3:  return "XAdES-EPES form, supported starting from XAdES v1.2.2"; break;
      case 4:  return "XAdES-T form";                                          break;
      case 5:  return "XAdES-C form";                                          break;
      case 6:  return "XAdES-X form";                                          break;
      case 7:  return "XAdES-X-L form";                                        break;
      case 8:  return "XAdES-A form";                                          break;
      case 9:  return "XAdES-E-BES form";                                      break;
      case 10: return "XAdES-E-EPES form";                                     break;
      case 11: return "XAdES-E-T form";                                        break;
      case 12: return "XAdES-E-C form";                                        break;
      case 13: return "XAdES-E-X form";                                        break;
      case 14: return "XAdES-E-X-Long form (type 1)";                          break;
      case 15: return "XAdES-E-X-L form (type 2)";                             break;
      case 16: return "XAdES-E-A form";                                        break;
      default: return "Unknown";                                               break;
    }
  }
}

  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $xadesverifier = new MyXAdESVerifier();
    $certmgr = new SecureBlackBox_CertificateManager();

    try {
      // General options
      $xadesverifier->setInputFile($_REQUEST['inputFile']);
      
      if(!empty($_REQUEST['detached'])){
        if(strcmp($_REQUEST['dataFile'], "") == 0){
          throw new Exception("A data file must be specified if the signature is detached.");
        }
        $xadesverifier->setDataFile($_REQUEST['dataFile']);
      }

      // Verification
      $xadesverifier->doVerify();
      
      echo "<h2>Verification Successful</h2>";
      echo "<h3>References</h3><br />";
      echo "<table>";
      echo $xadesverifier->getReferenceOutput();
      echo "</table><br />";
      
      echo "<table>";
      echo "<tr><td>XAdESVersion:</td><td>" . $xadesverifier->getXAdESVersionAsString() . "</td></tr>";
      echo "<tr><td>XAdESForm:</td><td>"    . $xadesverifier->getXAdESFormAsString()    . "</td></tr>";
      echo "</table>";
    }
    catch (exception $e) {
      echo "<h2>Verification Failure (Details Below)</h2><p>" . $e->getMessage() . "</p>";
    }
  }
?>

<br/>
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
