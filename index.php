<?php
require __DIR__ . '/SCTE35Parser.php';

$me = new SCTE35Parser();

$base64 = '';
if (isset($_GET['base64']) && !empty($_GET['base64']))
	$base64 = $_GET['base64'];
$error = null;
$json = null;
if (!empty($base64)) {
	try {
		$json = $me->parseFromBase64($base64);
	}
	catch (Exception $e) {
		$error = $e->message;
	}
}
?><html>
<head>
<title>SCTE35 Decoder</title>
<style type="text/css">
</style>
</head>
<body>
<form name="scte" method="GET">
Enter Base64 message : <br/>
<input type="text" size="80" name="base64" value="<?php echo $base64;?>"/>
<br/>
<br/>
<input type="submit">
</form>
<br/>
<a href="?base64=%2FDCgAAALyooYAP%2FwBQb%2FOleD8ACKAhxDVUVJMACBzn%2FAAAAAAAAICDE2M0pQMTA1MQADAhxDVUVJNAAH6X%2FAAABDKzAICDIwMjUAAAAANAAAAAACLENVRUkBAAfpf8AAAAAAAAwYISUiFyU3FUoJNxUAFh47GAYhFBtBEQ0NAQAAAhxDVUVJMACB0H%2FAAAAVPvAICDEyNTQxNjIAMAEDZWmHpw%3D%3D">TimeSignal example 1</a><br/>
<br/>
<?php if (!empty($error)) {
	echo '<h4>'.$error.'</h4>';
} ?>
<?php if (!empty($json)) { ?>
<br/>
<br/>
JSON output :
<pre>
<?php echo json_encode(json_decode($json), JSON_PRETTY_PRINT); ?>
</pre>
<?php } ?>
</body>
</html>	