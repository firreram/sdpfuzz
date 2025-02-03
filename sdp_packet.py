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

# Enhanced Data Element with proper length handling
class DataElement(Packet):
    name = "Data Element"
    fields_desc = [
        ByteField("type_size", 0),
        StrLenField("value", b"",
                    length_from=lambda pkt: (pkt.type_size & 0x07) + 1)
    ]
    
    def post_build(self, p, pay):
        # Auto-calculate type_size if not specified
        if self.type_size == 0 and self.value:
            size = len(self.value) - 1
            elem_type = 0x19  # UUID type
            p = bytes([(elem_type << 3) | size]) + p[1:]
        return p + pay

    def extract_uuid(self):
        elem_type = (self.type_size >> 3) & 0x1F
        size_indicator = self.type_size & 0x07
        
        if elem_type == 0x19:  # UUID type
            try:
                if size_indicator == 0x01:  # 16-bit UUID
                    return uuid.UUID(bytes=bytes([0])*14 + self.value)
                elif size_indicator == 0x03:  # 32-bit UUID
                    return uuid.UUID(bytes=bytes([0])*12 + self.value)
                elif size_indicator == 0x07:  # 128-bit UUID
                    return uuid.UUID(bytes=self.value)
            except:
                return "Invalid UUID"
        return None

# Enhanced Data Element Sequence with proper length calculation
class DataElementSequence(Packet):
    name = "Data Element Sequence"
    fields_desc = [
        ByteField("desc", 0x35),
        FieldLenField("length", None, fmt="H", length_of="elements",
                     adjust=lambda pkt,x: x + 3),  # Account for desc(1) + length(2)
        PacketListField("elements", None, DataElement,
                       length_from=lambda pkt: pkt.length - 3)
    ]

    def post_build(self, p, pay):
        # Auto-calculate length if not specified
        if self.length is None:
            elements_len = sum(len(e) for e in self.elements) if self.elements else 0
            total_len = elements_len + 3  # desc(1) + length(2)
            p = p[0:1] + struct.pack(">H", total_len) + p[3:]
        return p + pay

# Enhanced SDP Service Search Request
class SDP_ServiceSearchRequest(Packet):
    name = "SDP Service Search Request"
    fields_desc = [
        ByteField("pdu_id", 0x02),
        ShortField("tid", 0),
        FieldLenField("plen", None, fmt="H", length_of="payload",
                     adjust=lambda pkt,x: x + 5),  # Fixed header fields size
        PacketListField("service_search_pattern", None, DataElementSequence,
                       length_from=lambda pkt: pkt.plen - 5),
        ShortField("max_service_record_count", 10),
        ByteField("continuation_state_length", 0),
        StrLenField("continuation_state", b"", 
                   length_from=lambda x: x.continuation_state_length),
    ]

    def post_build(self, p, pay):
        # Auto-calculate plen if not specified
        if self.plen is None:
            payload_len = len(bytes(self.service_search_pattern)) if self.service_search_pattern else 0
            plen = payload_len + 5  # Fixed fields size
            p = p[:3] + struct.pack(">H", plen) + p[5:]
        return p + pay

def create_uuid_element(uuid_str):
    try:
        uuid_obj = uuid.UUID(uuid_str)
        elem = DataElement()
        
        if uuid_obj.version == 4:  # 128-bit UUID
            elem.value = uuid_obj.bytes
            elem.type_size = 0x19 | 0x07  # Type 0x19, size 0x07 (16 bytes)
        else:
            short_uuid = uuid_obj.int >> 96
            if short_uuid <= 0xFFFF:  # 16-bit UUID
                elem.value = struct.pack(">H", short_uuid)
                elem.type_size = 0x19 | 0x01  # Type 0x19, size 0x01 (2 bytes)
            else:  # 32-bit UUID
                elem.value = struct.pack(">I", short_uuid)
                elem.type_size = 0x19 | 0x03  # Type 0x19, size 0x03 (4 bytes)
        return elem
    except ValueError:
        return None

def build_service_search_pattern(uuids):
    seq = DataElementSequence()
    seq.elements = [create_uuid_element(u.strip()) for u in uuids if u.strip()]
    return seq

# Modified SDP Service Search Response
class SDP_ServiceSearchResponse(Packet):
    name = "SDP Service Search Response"
    fields_desc = [
        ByteField("pdu_id", 0x03),
        ShortField("tid", 0),
        FieldLenField("plen", None, fmt="H", length_of="payload"),
        ShortField("total_service_records", 0),
        ShortField("current_service_records", 0),
        PacketListField("handle_list", None, DataElementSequence,
                       length_from=lambda pkt: pkt.plen - 5),
        ByteField("continuation_state_length", 0),
        StrLenField("continuation_state", b"", 
                   length_from=lambda x: x.continuation_state_length),
    ]

# helper function to build prot descriptor header
# idea is to have a unified area to build in case protocol spec changes 
def build_prot_descriptor_header(type_code, size_code):
    return type_code << 3 | size_code

def build_uuid_struct(uuid_str):
    print(f"UUID: {uuid_str}")
    uuid_type_code = TYPE_DESCRIPTOR_CODE["UUID"]
    uuid_size_code = SIZE_DESCRIPTOR_CODE["2Bytes"]
    uuid_obj = uuid.UUID(uuid_str)
    print(f"UUID obj: {uuid_obj}")
    # Determine UUID type and size
    if uuid_obj.version == 4:  # 128-bit UUID
        print("UUID is 128bits")
        uuid_size_code = SIZE_DESCRIPTOR_CODE["16Bytes"]
        elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
        value = uuid_obj.bytes
    else:  # 16/32-bit UUID
        print("UUID is not 128 bits")
        short_uuid = uuid_obj.int >> 96
        if short_uuid <= 0xFFFF:
            print("16 bits")
            elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
            value = struct.pack(">H", short_uuid)
        else:
            print("32 bits")
            uuid_size_code = SIZE_DESCRIPTOR_CODE["4Bytes"]
            elem_type = build_prot_descriptor_header(uuid_type_code, uuid_size_code)
            value = struct.pack(">I", short_uuid)
            
    uuid_struct = struct.pack("B", elem_type) + value
    return uuid_struct



def build_sdp_request(tid=0x0001, max_record=10, uuid_list=[ASSIGNED_SERVICE_UUID["Service Discovery Server"]]):
    # 1. Build Data Elements
    data_elements = []
    print("Building UUID data elements")
    data_seq_type_code = TYPE_DESCRIPTOR_CODE["Data Element Sequence"]
    data_seq_size_code = SIZE_DESCRIPTOR_CODE["Data_Size_Additional_8_bits"]
    data_seq_header = struct.pack("B",build_prot_descriptor_header(data_seq_type_code, data_seq_size_code))
    
    print("Building UUID elements")
    for uuid_str in uuid_list:
        uuid_struct = build_uuid_struct(uuid_str)       
        data_elements.append(uuid_struct)
        
    print(data_elements)
    # 2. Build Data Element Sequence
    elements_payload = b"".join(data_elements)
    payload_len = len(elements_payload)
    #seq_len = len(elements_payload) + 3
    print(f"Data Element Sequence length = {payload_len}")
    seq_header = data_seq_header + struct.pack(">B", payload_len) 
    service_search_pattern = seq_header + elements_payload

    # 3. Build SDP Request
    pdu_header = struct.pack(">BHH", 
                           0x02,  # PDU ID
                           tid,  # Transaction ID
                           len(service_search_pattern) + 3)  # plen
    
    max_records = struct.pack(">H", max_record)  # Max service records
    continuation = b"\x00"  # No continuation state

    return pdu_header + service_search_pattern + max_records + continuation

def parse_sdp_response(response):
    # Basic response parsing
    try:
        pdu_id = response[0]
        if pdu_id != 0x01:
            tid = struct.unpack(">H", response[1:3])[0]
            plen = struct.unpack(">H", response[3:5])[0]
            total_records = struct.unpack(">H", response[5:7])[0]
            current_records = struct.unpack(">H", response[7:9])[0]
            
            print(f"SDP Response (TID: {tid:04x})")
            print(f"Total Records: {total_records}")
            print(f"Current Records: {current_records}")
            
            # Parse handle list
            handle_data = response[9:-2]  # Skip continuation state
            if handle_data.startswith(b"\x35"):
                seq_len = struct.unpack(">H", handle_data[1:3])[0]
                print(f"Found {seq_len - 3} bytes of handle data")
        else: #SDP Response Error
            print("SDP Response error")
            
    except Exception as e:
        print(f"Parse error: {str(e)}")