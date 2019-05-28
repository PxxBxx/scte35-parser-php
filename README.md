# scte35-parser-php
class to parse SCTE35 messages, be they SpliceInsert or TimeSignal

_Sorry, new to public repositories._

After checkout, run composer install and launch the test example :

`php test.php`

```
<?php
require __DIR__ . '/SCTE35Parser.php';

$me = new SCTE35Parser();

// TimeSignal Example
$json = $me->parseFromBase64('/DCAAAAMc3RIAP/wBQb/mZSU8ABqAhxDVUVJMACB4H/AAAAAAAAICDEyMzk2MzQAMQIDAixDVUVJAQAH+H/AAAAAAAAMGCElIhclNxVKCTcVABYeOxj7ERUWMRENDQEAAAIcQ1VFSTAAgeN/wAAAGLggCAgxMjQyODY0ADADA8N+pPM=');
echo $json;
```

Should output a long json with the exploded SCTE35 binary structure.
`{"table_id":"fc","section_syntax_indicator":false,"private":false,"section_length":128,"protocol_version":0,"encrypted_packet":false,"encryption_algorithm":0,"pts_adjustment":208893000,"cw_index":0,"tier":"ff0f","splice_command_length":5,"splice_command_type":6,"splice_command":{"time_specified_flag":true,"pts_time":6871618800},"splice_descriptor_loop_length":106,"splice_descriptors":[{"identifier":1129661769,"segmentation_event_id":805339616,"segmentation_event_cancel_indicator":false,"program_segmentation_flag":true,"segmentation_duration_flag":true,"delivery_not_restricted_flag":false,"web_delivery_allawed_flag":false,"no_regional_blackout_flag":false,"archive_allowed_flag":false,"device_restrictions":0,"segmentation_duration":0,"segmentation_upid_type":8,"segmentation_upid_length":8,"segmentation_upid":"3132333936333400","segment_type_id":49,"segment_num":2,"segments_expected":3,"splice_descriptor_tag":2,"descriptor_length":28},{"identifier":1129661769,"segmentation_event_id":16779256,"segmentation_event_cancel_indicator":false,"program_segmentation_flag":true,"segmentation_duration_flag":true,"delivery_not_restricted_flag":false,"web_delivery_allawed_flag":false,"no_regional_blackout_flag":false,"archive_allowed_flag":false,"device_restrictions":0,"segmentation_duration":0,"segmentation_upid_type":12,"segmentation_upid_length":24,"segmentation_upid":"212522172537154a09371500161e3b18fb11151631110d0d","segment_type_id":1,"segment_num":0,"segments_expected":0,"splice_descriptor_tag":2,"descriptor_length":44},{"identifier":1129661769,"segmentation_event_id":805339619,"segmentation_event_cancel_indicator":false,"program_segmentation_flag":true,"segmentation_duration_flag":true,"delivery_not_restricted_flag":false,"web_delivery_allawed_flag":false,"no_regional_blackout_flag":false,"archive_allowed_flag":false,"device_restrictions":0,"segmentation_duration":1620000,"segmentation_upid_type":8,"segmentation_upid_length":8,"segmentation_upid":"3132343238363400","segment_type_id":48,"segment_num":3,"segments_expected":3,"splice_descriptor_tag":2,"descriptor_length":28}]}`

Note : A lot nicer when piping to jq

be free to use, comment, issue, I had a hell of a time searching for a functional PHP lib to do that (Python lovers have everything they want in this domain, but not PHP mammoth).

Cheers.
