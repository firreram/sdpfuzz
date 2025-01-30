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
from sdp_packet import *


current_tranid = 0x0001


def parse_sdp_response(response):
    sdp_response = SDP_ServiceSearchResponse(response)
    sdp_response.show()
        
    # Parse service handles
    if sdp_response.pdu_id == 0x03:
        print("\n=== Parsed Response Details ===")
        print(f"Transaction ID: {hex(sdp_response.tid)}")
        print(f"Total Services: {sdp_response.total_service_records}")
        print(f"Current Services: {sdp_response.current_service_records}")
            
            # Parse handle list
        for seq in sdp_response.handle_list:
            if seq.desc == 0x35:  # Data Element Sequence
                for elem in seq.elements:
                    parsed_uuid = elem.extract_uuid()
                    if parsed_uuid:
                        print(f"Found Service Handle: {parsed_uuid}")

def sdp_fuzzing(bt_addr, test_info):
    print("SDP fuzzing WIP")
    
    try:
        print("Testing")
        
        service_uuids = [ASSIGNED_SERVICE_UUID["Public Browse Group"]]
        
        # Build service search pattern
        search_pattern = build_service_search_pattern([u.strip() for u in service_uuids])
        
        # Create request packet
        tid = random.randint(0, 0xFFFF)
        sdp_request = SDP_ServiceSearchRequest(
            tid=tid,
            service_search_pattern=[search_pattern],
            max_service_record_count=10
        )

        print("\n[+] Crafted SDP Request Packet:")
        sdp_request.show()    
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.connect((bt_addr, 1))  # SDP channel
        
        sock.send(bytes(sdp_request))
        print("\n[+] Sent SDP request to target device")
        
        # Receive response
        response = sock.recv(4096)
        print("\n[+] Received SDP response:")    
        parse_sdp_response(response)
    except Exception as e:
       print(e)