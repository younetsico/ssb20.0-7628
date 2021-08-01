<?php
$file = $_SERVER["QUERY_STRING"];
if ($file == "") $file = "seecode.php";
?>

<html>
<head>
<title>SecureBlackbox 2020 Demos - <% =file %> Source</title>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<meta name="description" content="SecureBlackbox 2020 Demos - <% =file %> Source"></head>

<body>

<div id="content">
<h1>SecureBlackbox - Demo Pages</h1>
<h2><% =file %> Source</h2>
<p>PHP source code for <% =file %>.</p>
<a href="default.php">[Other Demos]</a>
<a href="secureblackbox.chm">[Help]</a>
<hr/>

<center>
<table width="90%">
<tr>
<td>
<pre>

<?php
$code = file_get_contents($file);
$code = htmlentities($code);
$code = str_replace("&lt;%", "<FONT COLOR=blue>&lt;%", $code); 
$code = str_replace("%&gt;", "%&gt;</FONT>", $code); 
echo $code;
?>
</pre></td></tr></table></center>

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
<br/>
</div>

<div id="footer">
<center>
SecureBlackbox 2020 - Copyright (c) 2020 /n software inc. - All rights reserved. - For more information, please visit our website at <a href="http://www.nsoftware.com/?demopg-SBPFA" target="_blank">www.nsoftware.com</a>.</center></div>
</body></html>
