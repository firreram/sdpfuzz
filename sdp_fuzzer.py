import sys, os, subprocess
import json, datetime
import bluetooth
from statemachine import StateMachine, State
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict
from scapy.layers.bluetooth import L2CAP_Hdr
import struct


class SDP_ServiceSearchRequest(Packet):
   name = "SDP Service Search Request"
   fields_desc = [
       ByteField("pdu_id", 0x02),          # SDP_ServiceSearchRequest
       XShortField("trans_id", 0x1234),    # Transaction ID
       FieldLenField("param_len", None, length_of="params"),
   ]
class SDP_ServiceSearchPattern(Packet):
   name = "SDP Service Search Pattern"
   fields_desc = [
       ByteField("header", 0x35),          # Data Element Sequence
       ByteField("length", 0x03),          # Length of following data
       ByteField("uuid_type", 0x19),       # UUID16 type
       XShortField("uuid", 0x1108)         # Service UUID (Headset)
   ]
class SDP_SearchParams(Packet):
   name = "SDP Search Parameters"
   fields_desc = [
       PacketField("search_pattern", SDP_ServiceSearchPattern(), SDP_ServiceSearchPattern),
       ShortField("max_records", 0xFFFF),  # Maximum records to return
       ByteField("cont_state", 0x00)       # Continuation state
   ]

current_tranid = 0x0001

def sdp_fuzzing(bt_addr, test_info):
    print("SDP fuzzing WIP")
    
    try:
        print("Testing")
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.connect((bt_addr, 1))  # SDP uses L2CAP channel 1
        # Build protocol stack using Scapy
        sdp_params = SDP_SearchParams()
        sdp_request = SDP_ServiceSearchRequest(param_len=len(sdp_params))
        # Build L2CAP layer with automatic length calculation
        l2cap_packet = L2CAP_Hdr() / sdp_request / sdp_params
        # Show packet structure for verification
        l2cap_packet.show2()
        # Send raw packet bytes
        sock.send(raw(l2cap_packet))
        # Receive response
        response = sock.recv(1024)
        print(f"\nReceived response ({len(response)} bytes):")
        hexdump(response)        
        sock.close()
    except Exception as e:
       print(e)