<html>
<head>
<link rel="stylesheet" type="text/css" href="stylesheet.css">
<title>SecureBlackbox 2020 PHP Edition - Demos</title></head>

<body>

<div id="content">
<h1>SecureBlackbox 2020 PHP Edition &nbsp;-&nbsp; Demos</h1>

<font color=#111111>
NOTE: These pages are simple demos, and by no means complete applications.
They are intended to illustrate the usage of the SecureBlackbox components in a
simple, straightforward way. What we are hoping to demonstrate is how simple
it is to program with our tools. If you want to know more about them, or if 
you have questions, please visit
<a href="http://www.nsoftware.com/?demopg-SBPFA">www.nsoftware.com</a>
or email to <a href=mailto:support@nsoftware.com>support@nsoftware.com</a>.
<br/>
<br/>
<b>IMPORTANT:</b> In order to access the demo pages, you must first define a virtual
directory named <b>"/sbxphp20"</b> in your IIS server that 
points to this directory
and then connect to <a href="http://localhost/sbxphp20/default.php">
http://localhost/sbxphp20/default.php</a> to run the demos
(if you chose to do so during
setup, the directory should have been automatically created for you).
Then all you need to do is click on the PHP pages, and follow the 
on-screen instructions.
</font>

<h2>The following is the list of demos with short descriptions:</h2>
<hr/>

<center><table border=1 cellpadding=5 cols=3 frame=below width=90%>

<tr valign=TOP><td NOWRAP>
<a href="archivereader.php">archivereader.php</a>
<td>A simple Archive Reader sample created with the ArchiveReader component. Use it to read and extract files from archives.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="archivewriter.php">archivewriter.php</a>
<td>A simple Archive Writer sample created with the ArchiveWriter component. Use it to create and modify archives.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="asicsigner.php">asicsigner.php</a>
<td>A simple ASiC signer sample created with the ASiCSigner component. Use it to create XAdES-signed, CAdES-signed, and timestamped archives.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="asicverifier.php">asicverifier.php</a>
<td>A simple ASiC verifier created with the ASiCVerifier component. Use it to verify ASiC signatures.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="authenticodesigner.php">authenticodesigner.php</a>
<td>A simple authenticode signer created with the AuthenticodeSigner component. Use it to sign EXE and DLL files in accordance with MS Authenticode technology.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="authenticodeverifier.php">authenticodeverifier.php</a>
<td>A simple authenticode verifier based on the AuthenticodeVerifier component. Use it to verify signed EXE and DLL files.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="cadessigner.php">cadessigner.php</a>
<td>A simple CAdES generator created with the CAdESSigner component. The sample supports creation of CAdES signatures of different conformance levels.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="cadesverifier.php">cadesverifier.php</a>
<td>A simple CAdES processor created around the CAdESVerifier component.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="dcauth.php">dcauth.php</a>
<td>A simple example of the DC technology. The sample incorporates two counterparts of DC: the application part is represented with PDFSigner control, and the private key part is represented with DCAuth control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="hashfunction.php">hashfunction.php</a>
<td>Use this example to learn about calculate hash with HashFunction control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="jwencryption.php">jwencryption.php</a>
<td>Use this example to learn about encrypting and decrypting messages in JSON format with SymmetricCrypto control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="jwsigner.php">jwsigner.php</a>
<td>Use this example to learn about signing and verifying messages in JSON format with PublicKeyCrypto control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagecompressor.php">messagecompressor.php</a>
<td>A simple example of PKCS7-compliant message compressing functionality.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagedecompressor.php">messagedecompressor.php</a>
<td>This small example illustrates the PKCS7-compliant message decompressing functionality.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagedecryptor.php">messagedecryptor.php</a>
<td>A lightweight example of PKCS7 messaged decryption, built around the MessageDecryptor component.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messageencryptor.php">messageencryptor.php</a>
<td>This small demo illustrates the use of PKCS7 certificate-based messaged encryption functionality.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagesigner.php">messagesigner.php</a>
<td>Learn how to implement PKCS7 signing in your application with this simple example. MessageSigner is a simpler version of CAdESSigner, which excludes the AdES piece.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagetimestampverifier.php">messagetimestampverifier.php</a>
<td>This small demo shows how to validate PKCS7 timestamped messages with the MessageTimestampVerifier class.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messagetimestamper.php">messagetimestamper.php</a>
<td>This example illustrates the creation of PKCS7 timestamped messages.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="messageverifier.php">messageverifier.php</a>
<td>This sample illustrates the verification of signed PKCS7 documents. For advanced validations that include certificate chain processing see CAdESVerifier.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="officedecryptor.php">officedecryptor.php</a>
<td>A very simple office document decryptor app built using the OfficeDecryptor control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="officeencryptor.php">officeencryptor.php</a>
<td>A lightweight encryptor of Office documents.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="officesigner.php">officesigner.php</a>
<td>A simple example of Office document signing with OfficeSigner control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="officeverifier.php">officeverifier.php</a>
<td>Use this demo to learn how to verify signed Office document using the OfficeVerifier control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="passwordvault.php">passwordvault.php</a>
<td>A simple Password Vault to save user's information and passwords.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pdfdecryptor.php">pdfdecryptor.php</a>
<td>A simple PDF decryption example. Both certificate- and password-encrypted document types are supported.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pdfencryptor.php">pdfencryptor.php</a>
<td>A tiny PDF encryption example which supports password- and certificate-based encryption.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pdfsigner.php">pdfsigner.php</a>
<td>An easy-to-use PDF signing example. Both generic and PAdES signatures are supported.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pdfverifier.php">pdfverifier.php</a>
<td>This small demo illustrates the use of the PDFVerifier control for processing PDF signatures.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pgpreader.php">pgpreader.php</a>
<td>Use this easy-to-use example to learn about integrating PGP decryption and verification into your application.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pgpwriter.php">pgpwriter.php</a>
<td>A simple PGP encryptor-plus-verifier.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="pkcs11certificatestorage.php">pkcs11certificatestorage.php</a>
<td>An easy-to-use Certificate Storage for work with PKCS11 storages.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="publickeycrypto.php">publickeycrypto.php</a>
<td>Use this example to learn about sign and verify with PublicKeyCrypto control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="simpleauthenticator.php">simpleauthenticator.php</a>
<td>A simple Authenticator created with the Authenticator component. Use it to user authentication.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="simplepdfsigner.php">simplepdfsigner.php</a>
<td>An easy-to-use PDF signing example. Supported PKCS11 and Win32 storages.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="soapsigner.php">soapsigner.php</a>
<td>This small example illustrates the signing of SOAP messages with SOAPSigner control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="soapverifier.php">soapverifier.php</a>
<td>Use this example to learn about SOAP signature validation with SOAPVerifier control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="symmetriccrypto.php">symmetriccrypto.php</a>
<td>Use this example to learn about encrypt and decrypt with SymmetricCrypto control.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xadessigner.php">xadessigner.php</a>
<td>Use this demo to learn how to create signed XAdES documents of various levels.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xadesverifier.php">xadesverifier.php</a>
<td>This small demo illustrates the use of XAdESVerifier for XAdES signature validations.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xmldecryptor.php">xmldecryptor.php</a>
<td>A tiny XML decryption example.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xmlencryptor.php">xmlencryptor.php</a>
<td>A tiny XML encryption example.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xmlsigner.php">xmlsigner.php</a>
<td>This small example shows how to create basic XML signatures with XMLSigner control. See XAdESSigner for more sophisticated signatures.
</tr>
<tr valign=TOP><td NOWRAP>
<a href="xmlverifier.php">xmlverifier.php</a>
<td>This sample demonstrates the use of XMLVerifier for validating basic XML signatures. For validations involving certificate chain checks, see XAdESVerifier.
</tr>

</table></center></div>

<div id="footer">
<center>
SecureBlackbox 2020 - Copyright (c) 2020 /n software inc. - All rights reserved. - For more information, please visit our website at <a href="http://www.nsoftware.com/?demopg-SBPFA" target="_blank">www.nsoftware.com</a>.</center></div>
</body>
</html>

