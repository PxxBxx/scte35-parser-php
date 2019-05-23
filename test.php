<?php
require __DIR__ . '/SCTE35Parser.php';

$me = new SCTE35Parser();

// TimeSignal Example
$json = $me->parseFromBase64('/DCAAAAMc3RIAP/wBQb/mZSU8ABqAhxDVUVJMACB4H/AAAAAAAAICDEyMzk2MzQAMQIDAixDVUVJAQAH+H/AAAAAAAAMGCElIhclNxVKCTcVABYeOxj7ERUWMRENDQEAAAIcQ1VFSTAAgeN/wAAAGLggCAgxMjQyODY0ADADA8N+pPM=');
echo $json;

