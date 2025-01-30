import sys, os, subprocess
import json, datetime
import bluetooth
from statemachine import StateMachine, State
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
import struct



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


# Define SDP Data Element types
class DataElement(Packet):
    name = "Data Element"
    fields_desc = [
        ByteField("type_size", 0),
        StrLenField("value", b"",
                    length_from=lambda pkt: (pkt.type_size & 0x07) + 1)
    ]
    
    def extract_uuid(self):
        elem_type = (self.type_size >> 3) & 0x1F
        size_indicator = self.type_size & 0x07
        
        if elem_type == 0x19:  # UUID type
            if size_indicator == 0x01:  # 16-bit UUID
                return struct.unpack(">H", self.value)[0]
            elif size_indicator == 0x03:  # 128-bit UUID
                return uuid.UUID(bytes=self.value)
        return None

class DataElementSequence(Packet):
    name = "Data Element Sequence"
    fields_desc = [
        ByteField("desc", 0x35),  # Data Element Sequence descriptor
        FieldLenField("length", None, fmt="H", length_of="elements"),
        PacketListField("elements", None, DataElement,
                       length_from=lambda pkt: pkt.length)
    ]

# Modified SDP Service Search Request
class SDP_ServiceSearchRequest(Packet):
    name = "SDP Service Search Request"
    fields_desc = [
        ByteField("pdu_id", 0x02),
        ShortField("tid", 0),
        FieldLenField("plen", None, fmt="H", length_of="payload"),
        PacketListField("service_search_pattern", None, DataElementSequence,
                       length_from=lambda pkt: pkt.plen - 5),
        ShortField("max_service_record_count", 0xFFFF),
        ByteField("continuation_state_length", 0),
        StrLenField("continuation_state", b"", 
                   length_from=lambda x: x.continuation_state_length),
    ]

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

def create_uuid_element(uuid_str):
    try:
        uuid_obj = uuid.UUID(uuid_str)
        elem = DataElement()
        
        if uuid_obj.version == 4:  # 128-bit UUID
            elem.type_size = 0x19 | (0x07 << 3)  # Type 0x19 (UUID), size 0x07 (16 bytes)
            elem.value = uuid_obj.bytes
        else:  # 16/32-bit UUID
            short_uuid = uuid_obj.int >> 96
            if short_uuid <= 0xFFFF:  # 16-bit UUID
                elem.type_size = 0x19 | (0x01 << 3)  # Size 0x01 (2 bytes)
                elem.value = struct.pack(">H", short_uuid)
            else:  # 32-bit UUID
                elem.type_size = 0x19 | (0x03 << 3)  # Size 0x03 (4 bytes)
                elem.value = struct.pack(">I", short_uuid)
        return elem
    except ValueError:
        return None

def build_service_search_pattern(uuids):
    seq = DataElementSequence()
    seq.elements = [create_uuid_element(u) for u in uuids if create_uuid_element(u)]
    return seq