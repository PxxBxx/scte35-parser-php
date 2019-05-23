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
		return json_encode($this->splice);
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
		$toReturn = array();
		while ($length > 2 && $this->iterator->key() < ($this->bitarray->size - 16)) {
			$desc_tag = bindec($this->read(8));
			$desc_len = bindec($this->read(8));
			$length -= 2;
			$length -= $desc_len;

			switch ($desc_tag) {
				case 0x0:
					$splice_desc = $this->parseAvailDescriptor($desc_len);
					break;
				case 0x2:
					$splice_desc = $this->parseSegmentationDescriptor($desc_len);
					break;
				default:
					$splice_desc = new stdClass();
					if ($desc_len > 0)
						$splice_desc->raw = $this->binaryStringToHex($this->read($desc_len*8));
			}
			$splice_desc->splice_descriptor_tag = $desc_tag;
			$splice_desc->descriptor_length = $desc_len;
			$toReturn[] = $splice_desc;
		}
		return $toReturn;
	}

	private function parseAvailDescriptor($length) {
		$desc = new stdClass();
		$desc->identifier = bindec($this->read(32));
		$desc->providier_avail_id = bindec($this->read(32));
		return $desc;
	}

	private function parseSegmentationDescriptor($length) {
		$desc = new stdClass();
		$desc->identifier = bindec($this->read(32));
		$desc->segmentation_event_id = bindec($this->read(32));
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
			}
			$desc->segmentation_upid_type = bindec($this->read(8));
			$desc->segmentation_upid_length = bindec($this->read(8));
			$desc->segmentation_upid = $this->binaryStringToHex($this->read(8*$desc->segmentation_upid_length));

			$desc->segment_type_id = bindec($this->read(8));
			$desc->segment_num = bindec($this->read(8));
			$desc->segments_expected = bindec($this->read(8));
		}
		return $desc;
	}

	private function parseSpliceTime() {
		$splice_time = new stdClass();
		$splice_time->time_specified_flag = (bool)$this->read(1);
		if ($splice_time->time_specified_flag) {
			$this->read(6); // reserved
			$splice_time->pts_time = bindec($this->read(33));
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

	private function read($len = 1) {
		$buff = '';
		for ($i=0; $i<$len; $i++) {
			$buff .= $this->iterator->current() ? 1 : 0;
			$this->iterator->next();
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

}


