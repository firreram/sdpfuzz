
from scapy.packet import Packet
from random import *
from collections import OrderedDict
import struct
import uuid
'''
This file contains the relevant enum dictionary for SDP requests and response. 
It also provides a few helper functions to generate garbage values for fuzzing.
'''

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

def generate_garbage_by_byte(byte_count=4, add_length=True):
	garbage_value = b""
	for _ in range(0,byte_count):
		rand_garbage = randrange(0x00, 0x100)
		garbage_value = garbage_value + struct.pack(">B", rand_garbage)
	garbage_length = len(garbage_value)
	garbage_value = (struct.pack(">B", garbage_length) if add_length else b"") + garbage_value
	return garbage_value	

def generate_garbage(add_length=True):
	rand_bit = randrange(0, 4)
	garbage_value = b""
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

def generate_large_garbage(add_length=True):
	rand_garbage_1 = randrange(0x0000000000000000, 0x10000000000000000)
	rand_garbage_2 = randrange(0x0000000000000000, 0x10000000000000000)
	garbage_value = struct.pack(">Q", rand_garbage_1) + struct.pack(">Q", rand_garbage_2)
	garbage_length = len(garbage_value)
	garbage_value = (struct.pack(">B", garbage_length) if add_length else b"") + garbage_value
	return garbage_value

# Strategy: append garbage to packet
def add_garbage_to_packet(packet, update_length=True):
	packet_header_wo_length = packet[0:3]
	packet_tail_wo_length = packet[5:]
	garbage_value = generate_garbage()

	new_length = len(packet_tail_wo_length) + len(garbage_value) if update_length else 0x00
	new_packet = packet_header_wo_length + struct.pack(">H", new_length) + packet_tail_wo_length + garbage_value
	return garbage_value, new_packet


# Strategy: bit flipping. More aggressive and more chances of getting SDP Error responses
# default to 5% of bit flipping
def flip_bits_in_packet(packet, mutation_rate=0.05): 
	packet_bytes = bytearray(packet)
	for i in range(5, len(packet_bytes)): # we start from index 5 as we do not want to touch the PDU_id, tran id and length
		if random() < mutation_rate:
			# Choose a random bit (0-7) to flip in this byte.
			bit_to_flip = 1 << randint(0, 7)
			packet_bytes[i] ^= bit_to_flip
	return bytes(packet_bytes)

#helper functions to fuzz the packet

def generate_fixed_attribute_list1():
	attr_list = []
	min_attr_id = 0x0000
	max_attr_id = 0xFFFF	
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

def generate_fixed_uuid_list1():
	uuid_list = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]

	return uuid_list   

def generate_uuid_list():
	list_range = randrange(0, 15)
	uuid_list = []
	if list_range > 0:
		for _ in range(0, list_range):
			my_choice = random()
			if my_choice < 0.7: #use uuid from assigned list
				rand_key = choice(list(ASSIGNED_SERVICE_UUID.keys()))
				uuid_list.append(ASSIGNED_SERVICE_UUID[rand_key])
			else: #random uuid
				random_uuid = uuid.uuid4()
				if my_choice < 0.9: #add base
					uuid_list.append(str(random_uuid))
				else:
					uuid_list.append(str(random_uuid))
	
	return uuid_list