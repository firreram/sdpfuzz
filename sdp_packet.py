import sys, os, subprocess
import json, datetime
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
import struct
import uuid


REQ_PDU_ID = {
	0x02 : "SDP_SERVICE_SEARCH_REQ",
	0x04 : "SDP_SERVICE_ATTR_REQ",
	0x06 : "SDP_SERVICE_SEARCH_ATTR_REQ"
}

RSP_PDU_ID = {
	0x01 : "SDP_ERROR_RSP",
	0x03 : "SDP_SERVICE_SEARCH_RSP",
	0x05 : "SDP_SERVICE_ATTR_RSP",
	0x07 : "SDP_SERVICE_SEARCH_ATTR_RSP"
}


ERROR_RSP_CODE = {
	0x0001: "Invalid/unsupported SDP version",
	0x0002: "Invalid Service Record Handle",
	0x0003: "Invalid request syntax",
	0x0004: "Invalid PDU Size",
	0x0005: "Invalid Continuation State",
	0x0006: "Insufficient Resources to satisfy Request"
}

ASSIGNED_SERVICE_UUID = {
	"Service Discovery Server": "00001000-0000-1000-8000-00805f9b34fb",
	"Browse Group Descriptor": "00001001-0000-1000-8000-00805f9b34fb",
	"Public Browse Group": "00001002-0000-1000-8000-00805f9b34fb",
	"Serial Port": "00001101-0000-1000-8000-00805f9b34fb",
	"LAN Access Using PPP": "00001102-0000-1000-8000-00805f9b34fb",
	"Dial-up Networking": "00001103-0000-1000-8000-00805f9b34fb",
	"OBEX Object Push": "00001105-0000-1000-8000-00805f9b34fb",
	"OBEX File Transfer": "00001106-0000-1000-8000-00805f9b34fb",
	"Headset": "00001108-0000-1000-8000-00805f9b34fb",
	"Audio Source": "0000110A-0000-1000-8000-00805f9b34fb",
	"Audio Sink": "0000110B-0000-1000-8000-00805f9b34fb",
	"AV Remote Control Target": "0000110C-0000-1000-8000-00805f9b34fb",
	"AV Remote Control": "0000110E-0000-1000-8000-00805f9b34fb",
	"Handsfree": "0000111E-0000-1000-8000-00805f9b34fb",
	"Personal Area Networking User": "00001115-0000-1000-8000-00805f9b34fb",
	"Message Access Server": "00001132-0000-1000-8000-00805f9b34fb"
}

TYPE_DESCRIPTOR_CODE = {
	"NULL": 0x00,
	"Unsigned Integer": 0x01,
	"Signed two’s-complement integer": 0x02,
	"UUID": 0x03,
	"Text String": 0x04,
	"Boolean": 0x05,
	"Data Element Sequence": 0x06,
	"Data Element alternative": 0x07,
	"URL": 0x08
}

SIZE_DESCRIPTOR_CODE = {
	"1Byte": 0x00,
	"2Bytes": 0x01,
	"4Bytes": 0x02,
	"8Bytes": 0x03,
	"16Bytes": 0x04,
	"Data_Size_Additional_8_bits": 0x05,
	"Data_Size_Additional_16_bits": 0x06,
	"Data_Size_Additional_32_bits": 0x07
}


SERVICE_ATTRIBUTE_ID = {
	0x0000 : {
		"name":"ServiceRecordHandle",
		"type_code": TYPE_DESCRIPTOR_CODE["Unsigned Integer"],
		"size_code": SIZE_DESCRIPTOR_CODE["4Bytes"]
	},
	0x0001 : {
		"name":"ServiceClassIDList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x0002 : {
		"name":"ProviderName",
		"type_code": TYPE_DESCRIPTOR_CODE["Text String"],
		"size_code": SIZE_DESCRIPTOR_CODE["2Bytes"] #not sure, use 16 bits first
	},
	0x0003 : {
		"name":"ServiceID",
		"type_code": TYPE_DESCRIPTOR_CODE["UUID"],
		"size_code": SIZE_DESCRIPTOR_CODE["4Bytes"] #not sure, use 16 bits first
	},
	0x0004 : {
		"name":"ProtocolDescriptorList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x000D : {
		"name":"AdditionalProtocolDescriptorList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x0005 : {
		"name":"BrowseGroupList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x0006 : {
		"name":"LanguageBaseAttributeIDList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x0007 : {
		"name":"ServiceInfoTimeToLive",
		"type_code": TYPE_DESCRIPTOR_CODE["Unsigned Integer"],
		"size_code": SIZE_DESCRIPTOR_CODE["4Bytes"] #not sure, use 16 bits first
	},
	0x0008 : {
		"name":"ServiceAvailability",
		"type_code": TYPE_DESCRIPTOR_CODE["Unsigned Integer"],
		"size_code": SIZE_DESCRIPTOR_CODE["1Byte"] #not sure, use 16 bits first
	},
	0x0009 : {
		"name":"BluetoothProfileDescriptorList",
		"type_code": TYPE_DESCRIPTOR_CODE["Data Element Sequence"],
		"size_code": SIZE_DESCRIPTOR_CODE["Data_Size_Additional_16_bits"] #not sure, use 16 bits first
	},
	0x000A : {
		"name":"DocumentationURL",
		"type_code": TYPE_DESCRIPTOR_CODE["URL"],
		"size_code": SIZE_DESCRIPTOR_CODE["16Bytes"] #not sure, use 16 bits first
	},
	0x000B : {
		"name":"ClientExecutableURL",
		"type_code": TYPE_DESCRIPTOR_CODE["URL"],
		"size_code": SIZE_DESCRIPTOR_CODE["16Bytes"] #not sure, use 16 bits first
	},
	0x000C : {
		"name":"IconURL",
		"type_code": TYPE_DESCRIPTOR_CODE["URL"],
		"size_code": SIZE_DESCRIPTOR_CODE["16Bytes"] #not sure, use 16 bits first
	},
}

# helper functions to save the parameter as a dictionary and allow the rebuilding of the packet from the dictionary
def build_packet_from_param_dict(param_dict=None):
	if param_dict is None:
		return None
	pdu_id = param_dict["pdu_id"]
	if pdu_id == 0x02:
		packet = build_sdp_search_request(param_dict["current_tranid"], 
                                    	param_dict["max_records"], 
                                     	param_dict["service_uuids"], 
                                      	param_dict["continuation_state"])
		return packet
	elif pdu_id == 0x04:
		packet = build_sdp_service_attr_request(param_dict["current_tranid"], 
                                          		param_dict["service_handle"], 
                                            	param_dict["max_attr_byte_count"], 
                                             	param_dict["attribute_ids"], 
                                              	param_dict["continuation_state"])
		return packet
	elif pdu_id == 0x06:
		packet = build_sdp_service_search_attr_request(param_dict["current_tranid"],
                                                 		param_dict["service_uuids"],
                                                   		param_dict["max_attr_byte_count"],
                                                     	param_dict["attribute_ids"],
                                                      	param_dict["continuation_state"])
		return packet
	return None

def build_parameter_dictionary(pdu_id=0x00, current_tranid=0x0001, service_handle=0x0000, service_uuids=[], attribute_ids=[], max_records=0, max_attr_byte_counts=0x0000, continuation_state=b'\x00',garbage_value=b'\x00' ):
	param_dict = {}
	param_dict["pdu_id"]=pdu_id
	param_dict["current_tranid"]=current_tranid
	param_dict["service_handle"]=service_handle
	param_dict["service_uuids"]=service_uuids
	param_dict["attribute_ids"]=attribute_ids
	param_dict["max_records"]=max_records
	param_dict["max_attr_byte_count"]=max_attr_byte_counts
	param_dict["continuation_state"]=continuation_state.hex()
	param_dict["garbage_value"]=garbage_value.hex()
	return param_dict

# helper function to build prot descriptor header
# idea is to have a unified area to build in case protocol spec changes 
def build_prot_descriptor_header(type_code, size_code):
	return type_code << 3 | size_code

# helper function to build the attribute ids or uuid data sequences
def build_attr_id_struct(attr_id, isRange=False):
	#print(f"Attr Id: {attr_id}")
	attr_type_code = TYPE_DESCRIPTOR_CODE["Unsigned Integer"]
	attr_size_code = SIZE_DESCRIPTOR_CODE["2Bytes"] if not isRange else SIZE_DESCRIPTOR_CODE["4Bytes"]
	elem_type = build_prot_descriptor_header(attr_type_code, attr_size_code)
	value = struct.pack(">H", attr_id) if not isRange else struct.pack(">I", attr_id)
	attr_struct = struct.pack("B", elem_type) + value
	return attr_struct

def build_uuid_struct(uuid_str):
	uuid_type_code = TYPE_DESCRIPTOR_CODE["UUID"]
	uuid_size_code = SIZE_DESCRIPTOR_CODE["2Bytes"]
	#print(f"Processing UUID: {uuid_str}")
	uuid_obj = uuid.UUID(uuid_str)
	# Determine UUID type and size
	if uuid_obj.version == 4:  # 128-bit UUID
		uuid_size_code = SIZE_DESCRIPTOR_CODE["16Bytes"]
		elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
		value = uuid_obj.bytes
	else:  # 16/32-bit UUID
		short_uuid = uuid_obj.int >> 96
		if short_uuid <= 0xFFFF:
			elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
			value = struct.pack(">H", short_uuid)
		else:
			uuid_size_code = SIZE_DESCRIPTOR_CODE["4Bytes"]
			elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
			value = struct.pack(">I", short_uuid)
			
	uuid_struct = struct.pack("B", elem_type) + value
	return uuid_struct
    

def build_attribute_list_pattern(attribute_list=[{"attribute_id":0x0001, "isRange":False}], to_fuzz=False):
	data_seq_type_code = TYPE_DESCRIPTOR_CODE["Data Element Sequence"]
	data_seq_size_code = SIZE_DESCRIPTOR_CODE["Data_Size_Additional_8_bits"]
	data_seq_header = struct.pack("B",build_prot_descriptor_header(data_seq_type_code, data_seq_size_code))
	data_elements = []
	for attr_id in attribute_list:
		if "attribute_id" in attr_id:
			isRange = attr_id["isRange"] if "isRange" in attr_id else False
			attr_struct = build_attr_id_struct(attr_id["attribute_id"], isRange)

			mychoice = random()
			if mychoice <= 0.5 and to_fuzz:
				garbage_value = generate_garbage(False)
				attr_struct = attr_struct + garbage_value
			data_elements.append(attr_struct)	
	elements_payload = b"".join(data_elements)
	payload_len = len(elements_payload)
	seq_header = data_seq_header + struct.pack(">B", payload_len)
	attribute_pattern = seq_header + elements_payload
	return attribute_pattern

def build_sdp_search_pattern(uuid_list, to_fuzz=False):
	data_elements = []
	data_seq_type_code = TYPE_DESCRIPTOR_CODE["Data Element Sequence"]
	data_seq_size_code = SIZE_DESCRIPTOR_CODE["Data_Size_Additional_8_bits"]
	data_seq_header = struct.pack("B",build_prot_descriptor_header(data_seq_type_code, data_seq_size_code))
	
	for uuid_str in uuid_list:
		uuid_struct = build_uuid_struct(uuid_str)
		mychoice = random()
		if mychoice <= 0.5 and to_fuzz:
			garbage_value = generate_garbage(False)
			uuid_struct = uuid_struct + garbage_value
		data_elements.append(uuid_struct)
		
	# 2. Build Data Element Sequence
	elements_payload = b"".join(data_elements)
	payload_len = len(elements_payload)
	#seq_len = len(elements_payload) + 3
	seq_header = data_seq_header + struct.pack(">B", payload_len) 
	service_search_pattern = seq_header + elements_payload
	return service_search_pattern

#helper functions to fuzz the packet

def generate_fixed_attribute_list1():
	attr_list = []
	min_attr_id = 0x0000
	max_attr_id = 0xFFFF	
	current_attr_id = min_attr_id
	attr_dict = {"attribute_id": min_attr_id, "isRange": False}
	attr_list.append(attr_dict)
	attr_dict = {"attribute_id": ((min_attr_id+1)<<16) | (max_attr_id-1), "isRange": True}
	attr_list.append(attr_dict)
	attr_dict = {"attribute_id": max_attr_id, "isRange": False}
	attr_list.append(attr_dict)
	return attr_list

def generate_attribute_list():
	min_attr_id = 0x0000
	max_attr_id = 0xFFFF
	attr_list = []
	current_attr_id = min_attr_id
	while current_attr_id <= max_attr_id:
		choice1 = random()
		if choice1 < 0.5 or current_attr_id == max_attr_id:
			attr_dict = {"attribute_id": current_attr_id, "isRange": False}
			attr_list.append(attr_dict)
			current_attr_id += 1
		else:
			upper_limit = randrange(current_attr_id+1, max_attr_id)
			upper_limit = max(upper_limit, max_attr_id)
			attribute_range = (current_attr_id << 16) | upper_limit
			attr_dict = {"attribute_id": attribute_range, "isRange": True}
			attr_list.append(attr_dict)
			current_attr_id += 1
	return attr_list

def generate_fixed_uuid_list():
	uuid_list = []
	assigned_uuid_list_keys = list(ASSIGNED_SERVICE_UUID.keys())
	randomized_list_keys = sample(assigned_uuid_list_keys, 12)
	for key in randomized_list_keys:
		uuid_list.append(ASSIGNED_SERVICE_UUID[key])

	return uuid_list

def generate_uuid_list():
	list_range = randrange(0, 15)
	uuid_list = []
	if list_range > 0:
		for i in range(0, list_range):
			my_choice = random()
			if my_choice < 0.7: #use uuid from assigned list
				rand_key = choice(list(ASSIGNED_SERVICE_UUID.keys()))
				uuid_list.append(ASSIGNED_SERVICE_UUID[rand_key])
			else: #random uuid
				random_uuid = uuid.uuid4()
				if my_choice < 0.9: #add base
					# random_part = random_uuid.hex[:20]
					# custom_uuid = f"{random_part[:8]}-{random_part[8:12]}-{random_part[12:16]}-1000-8000-00805f9b34fb"
					uuid_list.append(str(random_uuid))
				else:
					uuid_list.append(str(random_uuid))
	
	return uuid_list
	
def generate_sdp_service_search_packet_for_fuzzing(current_tranid):
	uuid_list = generate_fixed_uuid_list()
	garbage_value = b"\x00"
	continuation_state = garbage_value
	my_choice = random()
	strategy = ""

	strategy = "sdp_service_search_empty_list" if len(uuid_list) == 0 else ("sdp_service_search_overload_list" if len(uuid_list) > 12 else "")
	if my_choice < 0.5 and len(strategy) == 0:
		garbage_value = generate_garbage()
		continuation_state = garbage_value
		strategy = "add_garbage_continuation_state"
  
	param_dict, packet = build_sdp_search_request(tid=current_tranid,
                                               		max_record=0xFFFF,
                                                 	uuid_list=uuid_list,
                                                  	continuation_state=continuation_state)
	if len(strategy) == 0: #no strategy yet
		strategy, garbage_value, packet = mutate_packet_for_fuzzing(packet)
	param_dict["garbage_value"] = garbage_value.hex()
	return param_dict, strategy, packet

def generate_sdp_service_attr_packet_for_fuzzing(current_tranid, service_handle):
	attr_list = generate_fixed_attribute_list1()
	garbage_value = b"\x00"
	continuation_state = garbage_value
	my_choice = random()
	strategy = ""
	if my_choice < 0.5:
		garbage_value = generate_garbage()
		continuation_state = garbage_value
		strategy = "add_garbage_continuation_state"
	
	param_dict, packet = build_sdp_service_attr_request(tid=current_tranid, 
                                                     	service_record_handle=service_handle,
                                                      	max_attr_byte_count=randrange(0x0007, 0x10000),
                                                       	attribute_list=attr_list,
                                                        continuation_state=continuation_state)
	if len(strategy) == 0:
		strategy, garbage_value, packet = mutate_packet_for_fuzzing(packet)
	
	param_dict["garbage_value"] = garbage_value.hex()
	return param_dict, strategy, packet

def generate_sdp_service_search_attr_packet_for_fuzzing(current_tranid, continuation_state):
	uuid_list = generate_fixed_uuid_list()
	attr_list = generate_fixed_attribute_list1()
	strategy = ""
	garbage_value = b"\x00"
	if continuation_state == b"\x00":

		my_choice = random()

		if my_choice < 0.5:
			garbage_value = generate_garbage()
			continuation_state = garbage_value
			strategy = "add_garbage_continuation_state"
   
	param_dict, packet = build_sdp_service_search_attr_request(tid=current_tranid, 
                                                            	uuid_list=uuid_list, 
                                                             	max_attr_byte_count=randrange(0x0007, 0x10000),
                                                              	attribute_list=attr_list,
                                                               	continuation_state=continuation_state)
	if len(strategy) == 0:
		strategy, garbage_value, packet = mutate_packet_for_fuzzing(packet)
  
	param_dict["garbage_value"] = garbage_value.hex()
	return param_dict, strategy, packet


def mutate_packet_for_fuzzing(packet):
	my_choice = random()
	strategy = ""
	garbage_value = b'\x00'
	if my_choice < 0.8:  # Add garbage
		strategy = "add_garbage"
		garbage_value, new_packet = add_garbage_to_packet(packet)
	# elif my_choice < 0.9:  # modify length
	# 	strategy = "mod_length"
	# 	new_packet = modify_param_length_in_packet(packet)
	else: # flip bits
		strategy = "flip_bit"
		new_packet = flip_bits_in_packet(packet)
	return strategy, garbage_value, new_packet

def generate_garbage(add_length=True):
	rand_bit = randrange(0, 4)
	garbage_value = b""
	rand_garbage = 0x00
	if rand_bit == 0:
		rand_garbage = randrange(0x00, 0x100)
		garbage_value = struct.pack(">B", rand_garbage)
	elif rand_bit == 1:
		rand_garbage = randrange(0x0000, 0x10000)
		garbage_value = struct.pack(">H", rand_garbage)
	elif rand_bit == 2:
		rand_garbage = randrange(0x00000000, 0x100000000)
		garbage_value = struct.pack(">I", rand_garbage)
	else:
		rand_garbage = randrange(0x0000000000000000, 0x10000000000000000)
		garbage_value = struct.pack(">Q", rand_garbage)
	garbage_length = len(garbage_value)
	garbage_value = (struct.pack(">B", garbage_length) if add_length else b"") + garbage_value
	return garbage_value

# Strategy 1: append garbage to packet
def add_garbage_to_packet(packet):
	packet_header_wo_length = packet[0:3]
	packet_tail_wo_length = packet[5:]
	garbage_value = generate_garbage()

	new_length = len(packet_tail_wo_length) + len(garbage_value)
	new_packet = packet_header_wo_length + struct.pack(">H", new_length) + packet_tail_wo_length + garbage_value
	return garbage_value, new_packet

# Strategy 2: modify parameter length
def modify_param_length_in_packet(packet):
	packet_header_wo_length = packet[0:3]
	packet_tail_wo_length = packet[5:]
	param_len = len(packet_tail_wo_length)
	rand_modifier = randrange(-2, 3) #range from -2 to 2. Can be more aggressive, let's see how to go about it
	param_len += rand_modifier
	new_packet = packet_header_wo_length + struct.pack(">H", param_len) + packet_tail_wo_length
	return new_packet


# Strategy 3: bit flipping. More aggressive and more chances of getting SDP Error responses
# default to 5% of bit flipping
def flip_bits_in_packet(packet, mutation_rate=0.05): 
	packet_bytes = bytearray(packet)
	for i in range(5, len(packet_bytes)): # we start from index 5 as we do not want to touch the PDU_id, tran id and length
		if random() < mutation_rate:
			# Choose a random bit (0-7) to flip in this byte.
			bit_to_flip = 1 << randint(0, 7)
			packet_bytes[i] ^= bit_to_flip
	return bytes(packet_bytes)
	

def build_sdp_search_request(tid=0x0001, max_record=10, uuid_list=[ASSIGNED_SERVICE_UUID["Service Discovery Server"]], continuation_state=b'\x00', to_fuzz=False):	
	service_search_pattern = build_sdp_search_pattern(uuid_list, to_fuzz=to_fuzz)

	pdu_header = struct.pack(">BHH", 
						   0x02,  # PDU ID
						   tid,  # Transaction ID
						   len(service_search_pattern) + 2 + len(continuation_state)) 
	
	max_records = struct.pack(">H", max_record) 
	continuation = continuation_state 
	parameter_dict = build_parameter_dictionary(pdu_id=0x02, current_tranid=
                                           	tid,service_uuids=uuid_list, 
                                            max_records=max_record, 
                                            continuation_state=continuation_state)
	packet = pdu_header + service_search_pattern + max_records + continuation
	return parameter_dict, packet

def build_sdp_service_attr_request(tid=0x0001, service_record_handle=0x0001, max_attr_byte_count=0x0007, attribute_list=[{"attribute_id":0x0001, "isRange":False}],continuation_state=b'\x00', to_fuzz=False):
	attribute_pattern = build_attribute_list_pattern(attribute_list, to_fuzz=to_fuzz)
	
	pdu_header = struct.pack(">BHHIH",
							 0x04,
							 tid,
							 len(attribute_pattern) + 6 + len(continuation_state),
							 service_record_handle,
							 max_attr_byte_count)
	continuation = continuation_state
	parameter_dict = build_parameter_dictionary(pdu_id=0x04, 
                                             current_tranid=tid, 
                                             service_handle=service_record_handle,
                                             attribute_ids=attribute_list,
                                             max_attr_byte_counts=max_attr_byte_count,
                                             continuation_state=continuation_state)
	
	return parameter_dict, pdu_header + attribute_pattern + continuation

def build_sdp_service_search_attr_request(tid=0x0001, uuid_list=[ASSIGNED_SERVICE_UUID["Service Discovery Server"]],max_attr_byte_count=0x0007, attribute_list=[{"attribute_id":0x0001, "isRange":False}], continuation_state=b'\x00' , to_fuzz=False):
	#1) build search pattern first
	service_search_pattern = build_sdp_search_pattern(uuid_list, to_fuzz=to_fuzz)
 
	#2) build attribute pattern
	attribute_pattern = build_attribute_list_pattern(attribute_list, to_fuzz=to_fuzz)
 
	#3) calculate length, should be len(ssp) + len(ap) + len(max_attr_count) + len(continuation_state)
	pattern_length = len(service_search_pattern) + len(attribute_pattern) + 2 + len(continuation_state)
	
	#4) Build the struct for max_attr_count first
	max_attr_byte_count_pattern = struct.pack(">H", max_attr_byte_count)
 
	#put header together
	pdu_header = struct.pack(">BHH",
							0x06,
							tid,
							pattern_length
							)
 
	continuation = continuation_state
	parameter_dict = build_parameter_dictionary(pdu_id=0x06, 
                                             current_tranid=tid, 
                                             service_uuids=uuid_list, 
                                             attribute_ids=attribute_list, 
                                             max_attr_byte_counts=max_attr_byte_count,
                                             continuation_state=continuation_state)
	return parameter_dict, pdu_header + service_search_pattern + max_attr_byte_count_pattern + attribute_pattern + continuation
 
# parse response packets
# service search response - need to get the handle list if we want to follow up on the service attr req
def parse_sdp_service_search_response(response):
	ret_data = {
		"handle_list": None,
		"attribute_list": None
	}
	tid = struct.unpack(">H", response[1:3])[0]
	total_records = struct.unpack(">H", response[5:7])[0]
	current_records = struct.unpack(">H", response[7:9])[0]
	# Parse handle list
	handle_data = response[9:]  # Skip continuation state
	#print(f"Handle data: {handle_data}")
	start_index = 0
	next_index = 0
	handle_list = []
	for curr_index in range(current_records):
		start_index = curr_index * 4
		next_index = start_index + 4
		handle_raw = handle_data[start_index:next_index]
		#print(f"Handle raw:{handle_raw}")
		handle_id = struct.unpack(">I", handle_raw)
		handle_list.append(handle_id[0])
		#print(f"Handle record {curr_index+1}: {handle_id[0]:08x}")
	continuation_state = handle_data[next_index:]
	ret_data["handle_list"] = handle_list
	ret_data["continuation_state"] = continuation_state
	return ret_data

# service attr response - by right we do not need to parse the attribute list, but we still want to get the continuation state to see if we want to continue sending the req
def parse_sdp_service_attribute_response(response):
	ret_data = {
		"handle_list": None,
		"attribute_list": None
	}
	tid = struct.unpack(">H", response[1:3])[0]
	plen = struct.unpack(">H", response[3:5])[0]
	attr_byte_count = struct.unpack(">H", response[5:7])[0]
	continuation_state = response[7+attr_byte_count:]
	ret_data["continuation_state"] = continuation_state
	return ret_data
	

def parse_sdp_response(response):
	# Basic response parsing
	ret_data = {
		"handle_list": None,
		"attribute_list": None
	}
	try:
		pdu_id = response[0]
		#print(f"PDU ID of response: {pdu_id}")
		if pdu_id == 0x03:
			ret_data = parse_sdp_service_search_response(response)
			pass
		elif pdu_id == 0x05:
			#print("Service attribute response")
			ret_data = parse_sdp_service_attribute_response(response)
			pass
		elif pdu_id == 0x07:
			#print("Service search attribute response")
			ret_data = parse_sdp_service_attribute_response(response)
			pass
		else: #SDP Response Error
			#print("SDP Response error")
			ret_data["continuation_state"] = b"\x00"
		
	except Exception as e:	
		print(f"Parse error: {str(e)}")
	return ret_data
		
