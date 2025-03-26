import sys, os, subprocess
import json, datetime
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
import struct
import uuid
from sdp_util import *


# helper function to build prot descriptor header
# idea is to have a unified area to build in case protocol spec changes 
def build_prot_descriptor_header(type_code, size_code):
	return type_code << 3 | size_code

# helper function to build the attribute ids or uuid data sequences
def build_attr_id_struct(attr_id, is_range=False):
	#print(f"Attr Id: {attr_id}")
	attr_type_code = TYPE_DESCRIPTOR_CODE["Unsigned Integer"]
	attr_size_code = SIZE_DESCRIPTOR_CODE["2Bytes"] if not is_range else SIZE_DESCRIPTOR_CODE["4Bytes"]
	elem_type = build_prot_descriptor_header(attr_type_code, attr_size_code)
	value = struct.pack(">H", attr_id) if not is_range else struct.pack(">I", attr_id)
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
			is_range = attr_id["isRange"] if "isRange" in attr_id else False
			attr_struct = build_attr_id_struct(attr_id["attribute_id"], is_range)

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
	seq_header = data_seq_header + struct.pack(">B", payload_len) 
	service_search_pattern = seq_header + elements_payload
	return service_search_pattern


	
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

def generate_garbage_sdp_packet_for_fuzzing(current_tranid, pdu_id):
	param_dict, packet = build_garbage_sdp_package(tid=current_tranid, pdu_id=pdu_id)
	strategy = "full_garbage_packet"
	return param_dict, strategy, packet

def mutate_packet_for_fuzzing(packet):
	my_choice = random()
	strategy = ""
	garbage_value = b'\x00'
	if my_choice < 0.8:  # Add garbage
		strategy = "add_garbage"
		garbage_value, new_packet = add_garbage_to_packet(packet)
	else: # flip bits
		strategy = "flip_bit"
		new_packet = flip_bits_in_packet(packet)
	return strategy, garbage_value, new_packet

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

# Strategy: random garbage as body. This strategy is equivalent to just sending rubbish to the SDP server without considering the grammar. 
# Keeping this strategy around as a means to find any random bug that is otherwise undetectable by other strategies.
def build_garbage_sdp_package(tid=0x0001, pdu_id=0x01):
	mychoice = random()
	garbage_value = generate_large_garbage(add_length=False)
	packet_length = 0x00 if mychoice < 0.5 else len(garbage_value) #chance for a zero length packet with garbage
	pdu_header = struct.pack(">BHH", 
						   pdu_id,  # PDU ID
						   tid,  # Transaction ID
						   packet_length
						   )
	parameter_dict = build_parameter_dictionary(pdu_id=pdu_id, current_tranid=tid)
	packet = pdu_header + garbage_value
	return parameter_dict, packet

'''
Function to generate standard SDP requests and parse SDP responses
'''

# function to build a valid service search request
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

# function to build a valid service attr request
def build_sdp_service_attr_request(tid=0x0001, service_record_handle=0x0001, max_attr_byte_count=0x0007, attribute_list=[{"attribute_id":0x0001, "isRange":False}],continuation_state=b'\x00', to_fuzz=False):
	attribute_pattern = build_attribute_list_pattern(attribute_list, to_fuzz=to_fuzz)
	
	#srh = int.from_bytes(service_record_handle, byteorder="big")

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

# function to build a valid service search attr request
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
	

#parsing the response from the SDP server. For the purpose of fuzzing, we do not need to really read the attribute lists. But it is helpful to retrieve the continuation states.
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
		elif pdu_id == 0x05 or pdu_id == 0x07:
			#print("Service attribute response")
			ret_data = parse_sdp_service_attribute_response(response)
		else: #SDP Response Error
			#print("SDP Response error")
			ret_data["continuation_state"] = b"\x00"
		
	except Exception as e:	
		print(f"Parse error: {str(e)}")
	return ret_data
		
