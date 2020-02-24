<?php
require __DIR__ . '/vendor/autoload.php';

use chdemko\BitArray\BitArray;

class SCTE35Parser {
	private $bitarray;
	private $iterator;
	private $splice;

	public function __construct() {

	}

	public function parseFromBase64($base64) {
		$this->bitarray = BitArray::fromString($this->Base64toBinaryString($base64));
		$this->iterator = $this->bitarray->getIterator();
		$this->splice = new stdClass();
		$this->parse();
		if (($out = json_encode($this->splice)) === false) {
			switch (json_last_error()) {
				case JSON_ERROR_NONE:
					echo ' - No errors';
					break;
				case JSON_ERROR_DEPTH:
					echo ' - Maximum stack depth exceeded';
					break;
				case JSON_ERROR_STATE_MISMATCH:
					echo ' - Underflow or the modes mismatch';
					break;
				case JSON_ERROR_CTRL_CHAR:
					echo ' - Unexpected control character found';
					break;
				case JSON_ERROR_SYNTAX:
					echo ' - Syntax error, malformed JSON';
					break;
				case JSON_ERROR_UTF8:
					echo ' - Malformed UTF-8 characters, possibly incorrectly encoded';
					break;
				default:
					echo ' - Unknown error';
					break;
			}
			ob_start();
			print_r($this->splice);
			$out = ob_get_contents();
			ob_end_clean();
			return '-'.$out.'-';
		}
		return $out;
	}

	public function parseFromHex($hex) {
		// TODO
	}

	private function Base64toBinaryString($base64) {
		$str = '';
		$chars = str_split(base64_decode($base64));
		foreach ($chars as $c) {
			$str .= sprintf("%08b", ord($c));
		}
		return $str;
	}
	private function parse() {
		$table_id = $this->binaryStringToHex($this->read(8));
		if ($table_id !== 'fc')
			throw new Exception('table_id invalid - only 0xfc is supported');
		
		$splice = &$this->splice;
		
		$splice->table_id = $table_id;
		$splice->section_syntax_indicator = (bool)$this->read(1);
		$splice->private = (bool)$this->read(1);
		$this->read(2); // private
		$splice->section_length = bindec($this->read(12));
		$splice->protocol_version = bindec($this->read(8));
		$splice->encrypted_packet = (bool)$this->read(1);
		$splice->encryption_algorithm = bindec($this->read(6));
		$splice->pts_adjustment = bindec($this->read(33));
		$splice->pts_adjustment_text = $this->ptsTimeToString($splice->pts_adjustment);
		$splice->cw_index = bindec($this->read(8));
		$splice->tier = $this->binaryStringToHex($this->read(12));
		$splice->splice_command_length = bindec($this->read(12));
		$splice->splice_command_type = bindec($this->read(8));

		switch ($splice->splice_command_type) {
			case 5:
				$splice->splice_command = $this->parseSpliceInsert();
				break;
			case 6:
				$splice->splice_command = $this->parseTimeSignal();
				break;
			default:
				throw new Exception('splice_command_type '.$splice->splice_command_type.'not yet supported');
		}

		$splice->splice_descriptor_loop_length = bindec($this->read(16));
		$splice->splice_descriptors = array();
		if ($splice->splice_descriptor_loop_length > 0) {
			$splice->splice_descriptors = $this->parseSpliceDescriptors();
		}

	}

	private function parseSpliceInsert() {
		$splice_insert = new stdClass();
		$splice_insert->splice_id = bindec($this->read(32));
		$splice_insert->splice_event_cancel_indicator = (bool)$this->read(1);
		$this->read(7);
		if ($splice_insert->splice_event_cancel_indicator === false) {
			$splice_insert->out_of_network_indicator = (bool)$this->read(1);
			$splice_insert->program_splice_flag = (bool)$this->read(1);
			$splice_insert->duration_flag = (bool)$this->read(1);
			$splice_insert->splice_immediate_flag = (bool)$this->read(1);
			$this->read(4); // reserved
			if ($splice_insert->program_splice_flag && !$splice_insert->splice_immediate_flag)
				$splice_insert->splice_time = $this->parseSpliceTime();
			if (!$splice_insert->program_splice_flag) {
				$splice_insert->component_count = bindec($this->read(8));
				$splice_insert->components = array();
				for ($i=0; $i<$splice_insert->component_count; $i++) {
					$component = new stdClass();
					$component->tag = bindec($this->read(8));
					$component->splice_time = null;
					if ($splice_insert->splice_immediate_flag) {
						$component->splice_time = $this->parseSpliceTime();
					}
					$splice_insert->components[] = $component;
				}
			}
			if ($splice_insert->duration_flag)
				$splice_insert->break_duration = $this->parseBreakDuration();
			$splice_insert->unique_program_id = bindec($this->read(16));
			$splice_insert->avail_num = bindec($this->read(8));
			$splice_insert->avails_expected = bindec($this->read(8));
		}
		return $splice_insert;
	}

	private function parseTimeSignal() {
		return $this->parseSpliceTime();
	}

	private function parseSpliceDescriptors() {
		$length = $this->splice->splice_descriptor_loop_length;
		// TODO 2 bytes for sub-segments
		$toReturn = array();
		while ($length > 2 && $this->iterator->key() < ($this->bitarray->size - 16)) {
			$desc_tag = bindec($this->read(8));
			$desc_len = bindec($this->read(8));
			$length -= 2;
			$length -= $desc_len;
			switch ($desc_tag) {
				case 0: // AvailDescriptor
					$desc = $this->parseAvailDescriptor($desc_len);
					$desc->splice_descriptor_tag_text = 'AvailDescriptor';
					break;
				case 2: // SegmentationDescriptor
					$desc = $this->parseSegmentationDescriptor($desc_len);
					$desc->splice_descriptor_tag_text = 'SegmentationDescriptor';
					break;
				case 1: // DTMFDescriptor
					$desc = $this->parseDTMFDescriptor($desc_len);
					$desc->splice_descriptor_tag_text = 'DTMFDescriptor';
					break;
				case 3: // TimeDescriptor
				case 4: // AudioDescriptor
				default: // 0x05 - 0xFF Reserved for future SCTE splice_descriptors
					$desc = new stdClass();
					$desc->identifier = dechex(bindec($this->read(32)));
					$desc->identifier_text = (string)hex2bin($desc->identifier);
					if ($desc_len > 32)
						$desc->raw = '0x'.$this->binaryStringToHex($this->read(($desc_len-32)*8));
					$desc->splice_descriptor_tag_text = 'ReservedDescriptor';
			}
			$desc->splice_descriptor_tag = $desc_tag;
			$desc->descriptor_length = $desc_len;
			$toReturn[] = $desc;
		}
		return $toReturn;
	}

	private function parseAvailDescriptor($length) {
		$desc = new stdClass();
		if ($length >= 8) {
			$desc->identifier = dechex(bindec($this->read(32)));
			$desc->identifier_text = (string)hex2bin($desc->identifier);
			$desc->providier_avail_id = bindec($this->read(32));
		}
		return $desc;
	}

	private function parseSegmentationDescriptor($length) {
		$desc = new stdClass();
		$desc->identifier = dechex(bindec($this->read(32)));
		$desc->identifier_text = (string)hex2bin($desc->identifier);
		$firstByte = dechex(bindec($this->read(8)));
		$nextBytes = dechex(bindec($this->read(24)));
		$desc->segmentation_event_id = '0x'.sprintf("%02s%06s",$firstByte,$nextBytes);
		$desc->segmentation_event_id_text = '0x'.$firstByte.' '.hexdec($nextBytes);
		$desc->segmentation_event_cancel_indicator = (bool)$this->read(1);
		$this->read(7); // reserved
		if ($desc->segmentation_event_cancel_indicator === false) {
			$desc->program_segmentation_flag = (bool)$this->read(1);
			$desc->segmentation_duration_flag = (bool)$this->read(1);
			$desc->delivery_not_restricted_flag = (bool)$this->read(1);
			if ($desc->delivery_not_restricted_flag === false) {
				$desc->web_delivery_allawed_flag = (bool)$this->read(1);
				$desc->no_regional_blackout_flag = (bool)$this->read(1);
				$desc->archive_allowed_flag = (bool)$this->read(1);
				$desc->device_restrictions = bindec($this->read(2));
			} else {
				$this->read(5);
			}
			if ($desc->program_segmentation_flag === false) {
				$desc->component_count = bindec($this->read(8));
				$desc->components = array();
				for ($i=0; $i<$desc->component_count; $i++) {
					$component = new stdClass();
					$component->tag = bindec($this->read(8));
					$this->read(7);
					$component->pts_offset = bindec($this->read(33));
					$desc->components[] = $component;
				}
			}
			if ($desc->segmentation_duration_flag) {
				$desc->segmentation_duration = bindec($this->read(40));
				$desc->segmentation_duration_text = sprintf("%.03f", $desc->segmentation_duration / 90000);
			}
			$desc->segmentation_upid_type = bindec($this->read(8));
			$desc->segmentation_upid_length = bindec($this->read(8));
			switch ($desc->segmentation_upid_type) {
				case 12:
					// MPU - Managed Private UPID
					// 16 bytes for AFMM spec
					// length-16 for n*8 private_data
					$desc->segmentation_upid = $this->parseMPU($desc->segmentation_upid_length);
					break;
				default:
					$desc->segmentation_upid = $this->binaryStringToHex($this->read(8*$desc->segmentation_upid_length));
					// FIXME bogus string to put in JSON, must find a way to represent the upid
					//$desc->segmentation_upid_text = (string)hex2bin($desc->segmentation_upid);
					break;
			}
			//$desc->segmentation_upid = $this->binaryStringToHex($this->read(8*$desc->segmentation_upid_length));
			//$desc->segmentation_upid_text = mb_convert_encoding((string)hex2bin($desc->segmentation_upid), "UTF-8", "UTF-8");

			$desc->segment_type_id = bindec($this->read(8));
			$desc->segment_type_text = $this->getSegmentationTypeText($desc->segment_type_id);
			$desc->segment_num = bindec($this->read(8));
			$desc->segments_expected = bindec($this->read(8));
			if (in_array($desc->segment_type_id, array(52, 54)) && $length > 28 ) {
				$desc->sub_segment_num = bindec($this->read(8));
				$desc->sub_segments_expected = bindec($this->read(8));
			}
		}
		return $desc;
	}

	private function parseDTMFDescriptor($length) {
		$desc = new stdClass();
		$desc->identifier = dechex(bindec($this->read(32)));
		$desc->identifier_text = (string)hex2bin($desc->identifier);
		$desc->preroll = bindec($this->read(8));
		$desc->dtmf_count = bindec($this->read(3));
		$this->read(5);
		$desc->DTMF_char = array();
		for ($i=0; $i<$desc->dtmf_count; $i++) {
			$desc->DTMF_char[] = chr(bindec($this->read(8)));
		}
		return $desc;
	}

	private function parseSpliceTime() {
		$splice_time = new stdClass();
		$splice_time->time_specified_flag = (bool)$this->read(1);
		if ($splice_time->time_specified_flag) {
			$this->read(6); // reserved
			$splice_time->pts_time = bindec($this->read(33));
			$splice_time->pts_time_text = $this->ptsTimeToString($splice_time->pts_time);
		} else {
			$this->read(7);
		}
		return $splice_time;

	}

	private function parseBreakDuration() {
		$break_duration = new stdClass();
		$break_duration->auto_return = (bool)$this->read(1);
		$this->read(6);
		$break_duration->duration = bindec($this->read(33));
		return $break_duration;
	}

	private function parseMPU($length) {
		// 16 bytes for AFMM spec
		$mpu = new stdClass();
		
		/*$mpu->bytes = array();
		for ($i=0; $i<$length; $i++) {
			$mpu->bytes[] = $this->read(8);
		}
		$mpu->bytes_concat = implode("",$mpu->bytes);
		//$mpu->decode = base64_decode($mpu->bytes_concat);
		return $mpu;*/
		
		// Orig code - debug until length 16
		$mpu->format_identifier = pack('H*', base_convert($this->read(32), 2, 16));
		$mpu->version = bindec($this->read(8));
		$mpu->cni = $this->binaryStringToHex($this->read(16));
		$mpu->date = bindec($this->read(32));
		$mpu->code = bindec($this->read(16));
		$mpu->duration = bindec($this->read(24));
		// length-16 for n*8 private_data
		$mpu->private_data = array();
		if ($length > 16) {
			$nb = $length - 16;
			for ($i=0; $i<$nb; $i++) {
				$mpu->private_data[] = bindec($this->read(8));
			}
		}
		return $mpu;
	}

	private function read($len = 1) {
		$buff = '';
		for ($i=0; $i<$len; $i++) {
			$buff .= $this->iterator->current() ? 1 : 0;
			$this->iterator->next();
			if (!$this->iterator->valid())
				break;
		}
		return $buff;
	}

	private function binaryStringToHex($str) {
		$len = strlen($str);
		if ($len % 8 > 0) {
			$str = str_pad($str, $len % 8, '0', STR_PAD_LEFT);
		}
		$ar = str_split($str, 8);
		$buff = '';
		foreach ($ar as $a) {
			$hex = dechex(bindec($a));
			$buff .= sprintf("%02s",$hex);
		}
		return $buff;
	}

	private function getSegmentationTypeText($segmentationTypeId) {
		$id = sprintf("%02d", $segmentationTypeId);
		$mapSegmentationTypeId = array(
			'00' => '(0x00) Not Indicated',
			'01' => '(0x01) Content Identification',
			'02' => '(0x02) 	',
			'16' => '(0x10) Program Start',
			'17' => '(0x11) Program End',
			'18' => '(0x12) Program Early Termination',
			'19' => '(0x13) Program Breakaway',
			'20' => '(0x14) Program Resumption',
			'21' => '(0x15) Program Runover Planned',
			'22' => '(0x16) Program Runover Unplanned',
			'23' => '(0x17) Program Overlap Start',
			'24' => '(0x18) Program Blackout Override',
			'25' => '(0x19) Program Start – In Progress',
			'32' => '(0x20) Chapter Start',
			'33' => '(0x21) Chapter End',
			'34' => '(0x22) Break Start',
			'35' => '(0x23) Break End',
			'36' => '(0x24) Opening Credit Start',
			'37' => '(0x25) Opening Credit End',
			'38' => '(0x26) Closing Credit Start',
			'39' => '(0x27) Closing Credit End',
			'48' => '(0x30) Provider Advertisement Start',
			'49' => '(0x31) Provider Advertisement End',
			'50' => '(0x32) Distributor Advertisement Start',
			'51' => '(0x33) pected Distributor Advertisement End',
			'52' => '(0x34) Provider Placement Opportunity Start',
			'53' => '(0x35) Provider Placement Opportunity End',
			'54' => '(0x36) Distributor Placement Opportunity Start',
			'55' => '(0x37) Distributor Placement Opportunity End',
			'56' => '(0x38) Provider Overlay Placement Opportunity Start',
			'57' => '(0x39) Provider Overlay Placement Opportunity End',
			'58' => '(0x3A) Distributor Overlay Placement Opportunity Start',
			'59' => '(0x3B) Distributor Overlay Placement Opportunity End',
			'64' => '(0x40) Unscheduled Event Start',
			'65' => '(0x41) Unscheduled Event End',
			'80' => '(0x50) Network Start',
			'81' => '(0x51) Network End'
		);
		if (isset($mapSegmentationTypeId[$id]))
			return $mapSegmentationTypeId[$id];
		return 'unknown segmentation_type_id ('.$segmentationTypeId.')';
	}

	private function ptsTimeToString($pts_time) {
		$pts_sec = $pts_time / 90000;
		$sec = floor(($pts_sec*1000) % 60000) / 1000;
		$min = floor(($pts_sec - $sec) / 60) % 60;
		$hour = floor(($pts_sec - $sec - $min*60) / 3600);
		return sprintf("%02d:%02d:%06s", $hour, $min, sprintf("%.03f",$sec));
	}

}
